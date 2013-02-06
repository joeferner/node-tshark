'use strict';

var fs = require('fs');
var inherits = require('util').inherits;
var spawn = require('child_process').spawn;
// var Transform = require('stream').Transform || require('readable-stream/transform');
var Readable = require('stream').Readable || require('readable-stream/readable');
var async = require('async');
var pcapp = require('pcap-parser');
var temp = require('temp');

var AFFIXES = {
  prefix: 'node-tshark',
  suffix: '.pcap'
};

module.exports = Converter;

function Converter (options) {
  if (!(this instanceof Converter)) {
    return new Converter(options);
  }

  // Transform.call(this, options);
  Readable.call(this, options);

  var self = this;
  this.packets = [];
  this.q = async.queue(processPacket, 10);

  this.parser = pcapp.parse(options.file);
  this.parser.on('globalHeader', function (_globalHeader) {
    console.error('globalHeader');

    self.globalHeader = _globalHeader;
  });
  this.parser.on('packet', function (packet) {
    console.error('packet');

    return self.q.push(packet);
  });

  function processPacket (packet, callback) {
    if (!self.globalHeader) {
      return self.emit('error', new Error('Global header not found.'));
    }
    console.error('processPacket');

    return writePacketToTempFile(self.globalHeader, packet, function (err, tempFilePath) {
      if (err) {
        return self.emit('error', err);
      }
      console.error('writePacketToTempFile: ', tempFilePath);

      return runTShark(tempFilePath, function (err, results) {
        if (err) {
          return self.emit('error', err);
        }
        console.error('runTShark');

        return fs.unlink(tempFilePath, function (err) {
          if (err) {
            return self.emit('error', err);
          }
          console.error('fs.unlink');

          // self.emit('data', results);
          // self.push(results);
          self.packets.push(results);
          self.emit('_packet');
          return callback();
        });
      });
    });
  }
}

// inherits(Converter, Transform);
inherits(Converter, Readable);

// Converter.prototype._transform = function(chunk, outputFn, callback) {};
Converter.prototype._read = function (bytes, done) {
  // this._readableState

  // console.error('bytes: ', bytes);

  // console.error('readableState.buffer: ', this._readableState.buffer);
  // console.error('readableState.bufferSize: ', this._readableState.bufferSize);
  // console.error('readableState.length: ', this._readableState.length);
  // console.error('readableState.pipesCount: ', this._readableState.pipesCount);
  // console.error('readableState.pipeChunkSize: ', this._readableState.pipeChunkSize);

  if (this.packets.length) {
    handleRead.call(this);
  } else {
    console.error('waiting...');
    this.once('_packet', handleRead);
  }

  function handleRead () {
    var buf = Buffer.concat(this.packets);
    this.packets.splice(0);
    done(null, buf);
  }

};

function writePacketToTempFile(globalHeader, packet, callback) {
  return temp.open(AFFIXES, function(err, tempFile) {
    if (err) {
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

function runTShark (fileName, callback) {
  // var tsharkResults = '';
  var tsharkResults = [];
  var tsharkResultsLength = 0;
  var tsharkParams = ['-C', 'node-tshark', '-r', fileName, '-x', '-V'];
  var tshark = spawn('tshark', tsharkParams);
  tshark.stdout.on('data', function (data) {
    // tsharkResults += data.toString();
    tsharkResultsLength += data.length;
    tsharkResults.push(data);
  });
  tshark.stderr.on('data', function (data) {
    console.error('tshark error: ', data.toString());
  });
  tshark.on('close', function (code) {
    // I don't think 'close' even returns an exit code.
    if (code) {
      return callback(new Error('Unexpected return code from tshark: '+ code));
    }
    return callback(null, Buffer.concat(tsharkResults, tsharkResultsLength));
  });
}
