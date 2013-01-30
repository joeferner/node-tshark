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

var PACKET_TMP_DIR = path.resolve(__dirname, '../testData/tmp_packets');

var PcapConverter = module.exports = function() {
    events.EventEmitter.call(this);
  };

util.inherits(PcapConverter, events.EventEmitter);

PcapConverter.prototype.convertFile = function(fileName) {
  var self = this;
  // see testData/pcap2tshark.sh for command line options
  fs.stat(fileName, function(err, stats) {
    if(err) throw err;
    if(stats.isDirectory()) {
      walk(fileName, function(err, results) {
        results.forEach(function(file) {
          fileShark(file, self);
        });
      });
    } else {
      fileShark(fileName, self);
    }
  });
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
    if(err) return end(err);
    var pending = list.length;
    if(!pending) return end(null, results);
    list.forEach(function(file) {
      file = dir + '/' + file;
      fs.stat(file, function(err, stat) {
        if(stat && stat.isDirectory()) {
          walk(file, function(err, res) {
            results = results.concat(res);
            if(!--pending) end(null, results);
          });
        } else {
          if(file.substring(file.length - 5, file.length).match('.pcap')) {
            results.push(file);
          }
          if(!--pending) end(null, results);
        }
      });
    });
  });
}

// 
// Function name is subject to change, but I needed a placeholder
// 

function fileShark(file, self) {
  var baseName = file.substring(0, file.length - 5); //Remove .pcap
  var fileChild = exec("tshark -C node-tshark -r " + file + " -x -V > " + baseName + ".tshark", function(err, stdout, stderr) {
    if(err) {
      self.emit('error', err);
      throw err;
    }
    self.emit('data', stdout);
  });
}

PcapConverter.prototype.convertStream = function(fileName) {
  var self = this;

  // see testData/pcap2tshark.sh for command line options
  var baseName = fileName.path.substring(0, fileName.path.length - 5);

  //Read stream using pcap parser
  var parser = pcapp.parse(fileName.path);
  parser.on('globalHeader', function(header) {

    var id = 0;

    var pathToTSharkFile = path.join(PACKET_TMP_DIR, 'tmpp.tshark');
    console.log('pathToTSharkFile: ', pathToTSharkFile);
    var tsharkWriteStream = fs.createWriteStream(pathToTSharkFile);

    parser.on('packet', function(packet) {
      var pcapHeaderBuffer = new Buffer(24 + 16); //24 for global header, 16 for packet
      writeGlobalHeader(header, pcapHeaderBuffer);
      writePacketHeader(packet.header, pcapHeaderBuffer);

      var totalPacketBufferLength = header.length + packet.data.length;
      var packetBuffer = Buffer.concat([header, packet.data], totalPacketBufferLength);

      // console.log('\nheres the data: ', packet.data.toString());
      // var tempName = 'http_temp_' + crypto.randomBytes(16).toString('hex') + '.pcap';
      var tempName = 'http_temp_' + (++id) + '.pcap';

      var pathToPacket = path.join(PACKET_TMP_DIR, tempName);

      fs.writeFile(pathToPacket, packetBuffer, function(err) {
        if(err) {
          throw err;
        }

        var tshark = spawn('tshark', ['-C', 'node-tshark', '-r', pathToPacket, '-x', '-V']);

        var spawnId = 0;
        var tsharkPacketBuffers = [];
        tshark.stdout.on('data', function(data) {
          tsharkPacketBuffers.push(data);
        });

        tshark.stderr.on('data', function(data) {
          console.error('tshark error: ', data);
        });

        tshark.on('exit', function(code) {
          console.log('tsharkPacketBuffers.length: ', tsharkPacketBuffers.length);
          var tsharkPacketBuffer = Buffer.concat(tsharkPacketBuffers);
          tsharkWriteStream.write(tsharkPacketBuffer);
          console.log('tshark exited with code: ', code);


          console.log('pathToPacket 2:', pathToPacket);
          fs.unlink(pathToPacket, function(err) {
            if(err) {
              console.log('There was an error deleting the file');
              self.emit('error', err);
              throw err;
            }
            console.log('pathToPacket 3:', pathToPacket);
            // self.emit('data', stdout);
          });

        });
      });

    });
  });

  parser.on('end', function() {
    // Do end-y type things.
    console.log('parser on end!');
  });

};

PcapConverter.prototype.createStream = function (fileName) {
  var pcapConverterStream = new Stream();
  pcapConverterStream.readable = true;

  var parser = pcapp.parse(fileName);
  parser.on('globalHeader', function (globalHeader) {
    // packetCount needed for stream's end event
    var packetCount = 0;
    parser.on('packet', function (packet) {
      // Increment packetCount on each packet event
      packetCount++;

      // Create Header
      var pcapPacketHeaderBuffer = createPacketHeaderBuffer(globalHeader, packet.header);

      // Collate Header and Packet Data
      var totalPacketBufferLength = pcapPacketHeaderBuffer.length + packet.data.length;
      var pcapPacketBuffer = Buffer.concat([pcapPacketHeaderBuffer, packet.data], totalPacketBufferLength);

      // Write packet pcap to file
      var pathToPacket = 'http_temp_' + crypto.randomBytes(16).toString('hex') + '.pcap';
      pathToPacket = path.join(PACKET_TMP_DIR, pathToPacket);

      fs.writeFile(pathToPacket, pcapPacketBuffer, onWriteFile);

      function onWriteFile (writeFileErr) {
        if (writeFileErr) {
          console.error('Failed when attemping to write a pcap file. E: ', err);
          throw err;
        }

        // Run tshark
        var tsharkPacketBuffers = [];
        var tshark = spawn('tshark', ['-C', 'node-tshark', '-r', pathToPacket, '-x', '-V']);

        var tsharkDataCount = 0;
        var randy = crypto.randomBytes(8).toString('hex');
        tshark.stdout.on('data', function (data) {
          console.error('randy: %s, tsharkDataCount: %d', randy, ++tsharkDataCount);
          tsharkPacketBuffers.push(data);
        });

        tshark.stderr.on('data', function (data) {
          console.error('tshark error: ', data);
        });

        tshark.on('exit', onTSharkExit.bind(undefined, randy, tsharkPacketBuffers));
      }

      function onTSharkExit (randy, tsharkPacketBuffers, code) {
        console.error('randy: %s, tsharkPacketBuffers.length: %d', randy, tsharkPacketBuffers.length);

        // emit stream data
        tsharkPacketBuffers.forEach(function (e) {
          pcapConverterStream.emit('data', e);
        });

        // Remove temporary pcap file
        fs.unlink(pathToPacket, onUnlink);
      }

      function onUnlink (unlinkErr) {
        if (unlinkErr) {
          console.error('Failed when attemping to unlink a pcap file. E: ', unlinkErr);
          throw err;
        }

        // Decrement packetCount
        if (!(--packetCount)) {
          // emit stream end
          pcapConverterStream.emit('end');
        }
      }
    });
  });

  return pcapConverterStream;
};

function createPacketHeaderBuffer (globalHeader, packetHeader) {
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

function writeGlobalHeader(header, b) {
  // Magic Number
  b.writeUInt32LE(header.magicNumber, 0);
  // Major Version Number
  b.writeUInt16LE(header.majorVersion, 4);
  // Minor Version Number
  b.writeUInt16LE(header.minorVersion, 6);
  // GMT
  b.writeInt32LE(header.gmtOffset, 8);
  // Accuracy of Timestamps
  b.writeUInt32LE(header.timestampAccuracy, 12);
  // Max length of captured packets
  b.writeUInt32LE(header.snapshotLength, 16);
  // Data Link type
  b.writeUInt32LE(header.linkLayerType, 20);
}

function writePacketHeader(header, b) {
  // Timestamp - seconds
  b.writeUInt32LE(header.timestampSeconds, 24);
  // Timestamp - microseconds
  b.writeUInt32LE(header.timestampMicroseconds, 28);
  // Number of octets of packet saved in file
  b.writeUInt32LE(header.capturedLength, 32);
  // Actual length of packet
  b.writeUInt32LE(header.originalLength, 36);
}
