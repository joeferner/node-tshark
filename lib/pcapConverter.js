'use strict';

var child_process = require('child_process');
var exec = child_process.exec;
var spawn = child_process.spawn;
var pcapp = require('pcap-parser');
var crypto = require('crypto');
var util = require("util");
var events = require("events");
var fs = require('fs');
var path = require('path');
var Stream = require('stream');
var async = require('async');
var temp = require('temp');
var metrics = require('metrics');

var TEMP_PREFIX = 'node-tshark';
var PcapConverter = module.exports = function() {
  events.EventEmitter.call(this);
  this.metrics = {
    packetQueue: new metrics.Histogram.createUniformHistogram(),
    tsharkQueue: new metrics.Histogram.createUniformHistogram(),
    data: new metrics.Timer(),
    packetCount: new metrics.Timer(),
    startTime: new Date()
  };
};

util.inherits(PcapConverter, events.EventEmitter);

PcapConverter.prototype.convertFile = function(fileName) {
  var self = this;
  // see testData/pcap2tshark.sh for command line options
  fs.stat(fileName, function(err, stats) {
    if (err) {
      return self.emit('error', err);
    }
    if (stats.isDirectory()) {
      walk(fileName, function(err, results) {
        if (err) {
          return self.emit('error', err);
        }
        async.forEach(results, fileShark, function() {
          self.emit('end');
        });
      });
    } else {
      fileShark(fileName, function() {
        self.emit('end');
      });
    }
  });

  function fileShark(fileName, callback) {
    callback = callback || function() {};
    return runTShark(fileName, function(err, results) {
      if (err) {
        return self.emit('error', err);
      }
      self.emit('data', results);
      return callback();
    });
  }
};

// 
// Walk traverses a pathname and returns the set of files within.
// Usage: 
//   walk(process.env.PWD, function (err, results) {
//     if (err) throw err;
//     console.log(results);
//   });
// 

function walk(dir, end) {
  var results = [];
  fs.readdir(dir, function(err, list) {
    if (err) {
      return end(err);
    }
    var pending = list.length;
    if (!pending) {
      return end(null, results);
    }
    list.forEach(function(file) {
      file = dir + '/' + file;
      fs.stat(file, function(err, stat) {
        if (stat && stat.isDirectory()) {
          walk(file, function(err, res) {
            results = results.concat(res);
            if (!--pending) {
              end(null, results);
            }
          });
        } else {
          if (file.substring(file.length - 5, file.length).match('.pcap')) {
            results.push(file);
          }
          if (!--pending) {
            end(null, results);
          }
        }
      });
    });
  });
}

PcapConverter.prototype.convertStream = function(inputStream) {
  var self = this;

  var packetQueue = async.queue(function(packet, callback) {
    return processPacket(packet, function(err) {
      if (err) {
        self.emit('error', err);
      }
      return callback();
    });
  }, 1);
  var tsharkQueue = async.queue(function(tempFile, callback) {
    self.metrics.tsharkQueue.update(tsharkQueue.length());
    return processFile(tempFile, function(err, data) {
      if (err) {
        self.emit('error', err);
      }
      self.emit('data', data);
      if (isEnd()) {
        self.emit('end');
      }
      return callback();
    });
  }, 10);
  var globalHeader;
  var tempFile;
  var parser = pcapp.parse(inputStream);
  var parseOnEndOccured = false;
  parser.on('globalHeader', function(_globalHeader) {
    globalHeader = _globalHeader;
  });
  parser.on('packet', function(packet) {
    packetQueue.push(packet);
  });
  parser.on('end', function() {
    parseOnEndOccured = true;
  });

  function isEnd() {
    return packetQueue.length() == 0 && tsharkQueue.length() && parseOnEndOccured;
  }

  function processGroupOfPackets() {
    self.metrics.packetQueue.update(packetQueue.length());
    if (!tempFile) {
      if (isEnd()) {
        self.emit('end');
      }
      return;
    }
    var timePassed = new Date() - tempFile.createdOn;

    if ((timePassed >= 5000 && tempFile.packetCount > 0) || tempFile.packetCount >= 1000) {
      var oldTempFile = tempFile;
      tempFile = null;
      return fs.close(oldTempFile.fd, function(err) {
        if (err) {
          self.emit('error', err);
        }
        tsharkQueue.push(oldTempFile);
        self.metrics.tsharkQueue.update(tsharkQueue.length());
        return 0;
      });
    } else if (isEnd()) {
      self.emit('end');
    }
  }

  function processFile(tempFile, callback) {
    var tempFileName = tempFile.path.toString();
    self.metrics.data.update(tempFile.capturedLength);
    self.metrics.packetCount.update(tempFile.packetCount);
    return runTShark(tempFileName, function(err, results, oldName) {
      if (err) {
        return callback(err);
      }
      fs.unlink(tempFileName, function(err) {
        if (err) {
          return self.emit('error', err);
        }
        return 0;
      });
      return callback(null, results);
    });
  }

  function processPacket(packet, callback) {
    if (!globalHeader) {
      return callback(new Error('Global header not found.'));
    }

    return getOrOpenTempFile(function(err, tempFile) {
      if (err) {
        return callback(err);
      }

      return writePacket(tempFile, packet, function(err) {
        if (err) {
          return callback(err);
        }
        tempFile.packetCount++;
        tempFile.capturedLength += packet.header.capturedLength;
        processGroupOfPackets();
        return callback();
      });
    });
  }

  function getOrOpenTempFile(callback) {
    if (tempFile) {
      return callback(null, tempFile);
    } else {
      return temp.open(TEMP_PREFIX, function(err, newTempFile) {
        if (err) {
          return callback(err);
        }
        tempFile = newTempFile;
        tempFile.packetCount = 0;
        tempFile.capturedLength = 0;
        tempFile.createdOn = Date.now();

        var globalHeaderBuffer = createGlobalHeader(globalHeader);
        return fs.write(tempFile.fd, globalHeaderBuffer, 0, globalHeaderBuffer.length, null, function(err) {
          if (err) {
            return callback(err);
          }
          return callback(null, tempFile);
        });
      });
    }
  }

  function writePacket(tempFile, packet, callback) {
    var packetHeaderBuffer = createPacketHeader(packet);
    return fs.write(tempFile.fd, packetHeaderBuffer, 0, packetHeaderBuffer.length, null, function(err) {
      if (err) {
        return callback(err);
      }
      return fs.write(tempFile.fd, packet.data, 0, packet.data.length, null, callback);
    });
  }
};

function runTShark(fileName, callback) {
  var tsharkResults = '';
  var tsharkParams = ['-C', 'node-tshark', '-r', fileName, '-x', '-V'];
  var tshark = spawn('tshark', tsharkParams);
  tshark.stdout.on('data', function(data) {
    tsharkResults += data.toString();
  });
  tshark.stderr.on('data', function(data) {
    console.error('tshark error: ', data.toString());
  });
  tshark.on('close', function(code) {
    if (code != 0) {
      return callback(new Error('Unexpected return code from tshark: ' + code));
    }
    return callback(null, tsharkResults, fileName);
  });
}

function createGlobalHeader(globalHeader) {
  var packetHeaderBuffer = new Buffer(24); // 24 for global header
  // 
  // Global Header
  // 
  // Magic Number
  packetHeaderBuffer.writeUInt32LE(globalHeader.magicNumber, 0);
  // Major Version Number
  packetHeaderBuffer.writeUInt16LE(globalHeader.majorVersion, 4);
  // Minor Version Number
  packetHeaderBuffer.writeUInt16LE(globalHeader.minorVersion, 6);
  // GMT
  packetHeaderBuffer.writeInt32LE(globalHeader.gmtOffset, 8);
  // Accuracy of Timestamps
  packetHeaderBuffer.writeUInt32LE(globalHeader.timestampAccuracy, 12);
  // Max length of captured packets
  packetHeaderBuffer.writeUInt32LE(globalHeader.snapshotLength, 16);
  // Data Link type
  packetHeaderBuffer.writeUInt32LE(globalHeader.linkLayerType, 20);

  return packetHeaderBuffer;
}

function createPacketHeader(packet) {
  var packetHeaderBuffer = new Buffer(16);

  // Timestamp - seconds
  packetHeaderBuffer.writeUInt32LE(packet.header.timestampSeconds, 0);
  // Timestamp - microseconds
  packetHeaderBuffer.writeUInt32LE(packet.header.timestampMicroseconds, 4);
  // Number of octets of packet saved in file
  packetHeaderBuffer.writeUInt32LE(packet.header.capturedLength, 8);
  // Actual length of packet
  packetHeaderBuffer.writeUInt32LE(packet.header.originalLength, 12);

  return packetHeaderBuffer;
}

