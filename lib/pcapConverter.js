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

var TEMP_PREFIX = 'node-tshark';

var PcapConverter = module.exports = function () {
    events.EventEmitter.call(this);
  };

util.inherits(PcapConverter, events.EventEmitter);

PcapConverter.prototype.convertFile = function (fileName) {
  var self = this;
  // see testData/pcap2tshark.sh for command line options
  fs.stat(fileName, function (err, stats) {
    if (err) {
      return self.emit('error', err);
    }
    if (stats.isDirectory()) {
      walk(fileName, function (err, results) {
        if(err) {
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
      if(err){
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
  fs.readdir(dir, function (err, list) {
    if (err) return end(err);
    var pending = list.length;
    if (!pending) return end(null, results);
    list.forEach(function (file) {
      file = dir + '/' + file;
      fs.stat(file, function (err, stat) {
        if (stat && stat.isDirectory()) {
          walk(file, function (err, res) {
            results = results.concat(res);
            if (!--pending) end(null, results);
          });
        } else {
          if (file.substring(file.length - 5, file.length).match('.pcap')) {
            results.push(file);
          }
          if (!--pending) end(null, results);
        }
      });
    });
  });
}

PcapConverter.prototype.convertStream = function (inputStream) {
  var secondsPassed = 0;
  var packetCount = 0;
  var timer = setInterval(function () {
    console.log("Packets in queue:", q.length());
    console.log("Seconds Passed:", ++secondsPassed);
    console.log("Packets Obtained:", packetCount);
    if ((secondsPassed >= 10 && packetCount > 0) || packetCount >= 1000) {
      packetCount = 0;
      secondsPassed = 0;
      processPacket(null, function() {
        secondsPassed = 0;
      });
    }
  }, 1000);
  var self = this;
  var q = async.queue(processPacket, 1);
  q.drain = function () {
    // packetCount = 0;
    // secondsPassed = 0;
    // return processPacket(null, function (err) {
    //   if (err) {
    //     self.emit('error', err);
    //   }
    //   return self.emit('end');
    // });
  };

  //Read stream using pcap parser
  var globalHeader;
  var fileStarted = false;
  var tempFile;
  var parser = pcapp.parse(inputStream);
  parser.on('globalHeader', function (_globalHeader) {
    globalHeader = _globalHeader;
  });
  parser.on('packet', function (packet) {
    q.push(packet);
  });
  

  function processPacket(packet, callback) {
    if(!globalHeader) {
      return self.emit('error', new Error('Global header not found.'))
    }
    if (!fileStarted) {
      return writePacketToTempFile(globalHeader, packet, function(err, tempFilePath) {
        if(err) {
          return self.emit('error', err);
        }
        packetCount++;
        fileStarted = true;
        tempFile = tempFilePath;
        console.log(tempFile);
        return callback();
      });
    } else if (!packet) {
      fileStarted = false;
      //Run tshark on the file.
      return runTShark(tempFile, function (err, results, oldName) {
        if (err) {
          return self.emit('error', err);
        }
        fs.unlink(oldName, function (err) {
          if (err) {
            return self.emit('error', err);
          }
        });
        self.emit('data', results);
        return callback();
      });
    } else {
      return continueWritingPacketToTempFile(globalHeader, packet, tempFile, function (err) {
        ++packetCount;
        if(err) {
          return self.emit('error', err);
        }
        return callback();
      });
    }
  }
};

function runTShark(fileName, callback) {
  var tsharkResults = '';
  var tsharkParams = ['-C', 'node-tshark', '-r', fileName, '-x', '-V'];
  var tshark = spawn('tshark', tsharkParams);
  tshark.stdout.on('data', function (data) {
    tsharkResults += data.toString();
  });
  tshark.stderr.on('data', function (data) {
    console.error('tshark error: ', data.toString());
  });
  tshark.on('close', function (code) {
    if(code!=0) {
      return callback(new Error('Unexpected return code from tshark: '+ code));
    }
    return callback(null, tsharkResults, fileName);
  });
}

function continueWritingPacketToTempFile(globalHeader, packet, fileName, callback) {
    return async.series([
      function(callback) {
        var pcapPacketHeaderBuffer = createSinglePacketHeaderBuffer(packet.header);
        return fs.appendFile(fileName, pcapPacketHeaderBuffer, callback);
      },
      function(callback) { return fs.appendFile(fileName, packet.data, callback); }
    ], function(err) {
      if(err) {
        return callback(err);
      }
      return callback(null);
    });
}

function writePacketToTempFile(globalHeader, packet, callback) {
  return temp.open(TEMP_PREFIX, function(err, tempFile) {
    if(err){
      return callback(err);
    }

    return async.series([
      function(callback) {
        var pcapPacketHeaderBuffer = createPacketHeaderBuffer(globalHeader, packet.header);
        return fs.write(tempFile.fd, pcapPacketHeaderBuffer, 0, pcapPacketHeaderBuffer.length, null, callback);
      },
      function(callback) { return fs.write(tempFile.fd, packet.data, 0, packet.data.length, null, callback); },
      function(callback) { return fs.close(tempFile.fd, callback); }
    ], function(err) {
      if(err) {
        return callback(err);
      }
      return callback(null, tempFile.path);
    });
  });
}

function createPacketHeaderBuffer(globalHeader, packetHeader) {
  var packetHeaderBuffer = new Buffer(24 + 16); // 24 for global header, 16 for packet
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

  // 
  // Packet Header
  // 
  // Timestamp - seconds
  packetHeaderBuffer.writeUInt32LE(packetHeader.timestampSeconds, 24);
  // Timestamp - microseconds
  packetHeaderBuffer.writeUInt32LE(packetHeader.timestampMicroseconds, 28);
  // Number of octets of packet saved in file
  packetHeaderBuffer.writeUInt32LE(packetHeader.capturedLength, 32);
  // Actual length of packet
  packetHeaderBuffer.writeUInt32LE(packetHeader.originalLength, 36);

  return packetHeaderBuffer;
}

function createSinglePacketHeaderBuffer(packetHeader) {
  var packetHeaderBuffer = new Buffer(16);

  // 
  // Packet Header
  // 
  // Timestamp - seconds
  packetHeaderBuffer.writeUInt32LE(packetHeader.timestampSeconds, 0);
  // Timestamp - microseconds
  packetHeaderBuffer.writeUInt32LE(packetHeader.timestampMicroseconds, 4);
  // Number of octets of packet saved in file
  packetHeaderBuffer.writeUInt32LE(packetHeader.capturedLength, 8);
  // Actual length of packet
  packetHeaderBuffer.writeUInt32LE(packetHeader.originalLength, 12);

  return packetHeaderBuffer;
}
