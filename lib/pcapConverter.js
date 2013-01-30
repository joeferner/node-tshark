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

var PACKET_TMP_DIR = path.resolve(__dirname, '../testData/tmp_packets');

var PcapConverter = module.exports = function () {
    events.EventEmitter.call(this);
  };

util.inherits(PcapConverter, events.EventEmitter);

PcapConverter.prototype.convertFile = function (fileName) {
  var self = this;
  // see testData/pcap2tshark.sh for command line options
  fs.stat(fileName, function (err, stats) {
    if(err) throw err;
    if(stats.isDirectory()) {
      walk(fileName, function (err, results) {
        results.forEach(function (file) {
          fileShark(file, self);
        });
      });
    } else {
      fileShark(fileName, self);
    }
  });
};

PcapConverter.prototype.convertStream = function (fileName) {
  var self = this;

  //Global header information
  var magicNumber = 0;
  var majorVersion = 0;
  var minorVersion = 0;
  var gmtOffset = 0;
  var timestampAccuracy = 0;
  var snapshotLength = 0;
  var linkLayerType = 0;



  // see testData/pcap2tshark.sh for command line options
  var baseName = fileName.path.substring(0, fileName.path.length - 5);

  //Read stream using pcap parser
  var parser = pcapp.parse(fileName.path);
  parser.on('globalHeader', function(header) {
    magicNumber = header.magicNumber;
    majorVersion = header.majorVersion;
    minorVersion = header.minorVersion;
    gmtOffset = header.gmtOffset;
    timestampAccuracy = header.timestampAccuracy;
    snapshotLength = header.snapshotLength;
    linkLayerType = header.linkLayerType;

    var id = 0;

    parser.on('packet', function (packet) {


      //console.log(util.inspect(packet));
      //On "packet" event create .pcap file with that packet in it
      var header = new Buffer(24 + 16); //24 for global header, 16 for packet
      writeGlobalHeader(header);
      writePacketHeader(header);

      var totalPacketBufferLength = header.length + packet.data.length;

      var packetBuffer = Buffer.concat([header, packet.data], totalPacketBufferLength);


      // console.log('\nheres the data: ', packet.data.toString());
      // var tempName = 'http_temp_' + crypto.randomBytes(16).toString('hex') + '.pcap';
      var tempName = 'http_temp_' + (++id) + '.pcap';

      var pathToPacket = path.join(PACKET_TMP_DIR, tempName);

      // var writeStream = fs.createWriteStream(pathToPacket);
      // if (writeStream.write(packetBuffer)) {
      //   console.log('written');
      //   // writeStream.end();
      // } else {
      //   console.log('not written');
      //   // writeStream.end();
      // }
      // fs.writeFile(tempName, packet.data, function(err){

        // console.log('pathToPacket: ', pathToPacket)
        // pathToPacket:  /Users/seanpilk/NearInfinity/node-tshark/testData/tmp_packets/http_temp_18.pcap


      fs.writeFile(pathToPacket, packetBuffer, function (err) {
        if (err) {
          throw err;
        }

        console.log('saved!');

        var tshark = spawn('tshark', ['-C', 'node-tshark', '-r', pathToPacket, '-x', '-V']);

        var spawnId = 0;
        tshark.stdout.on('data', function (data) {
          console.log('tshark data ' + (++spawnId) + ': ', data.toString());
        });

        tshark.stderr.on('data', function (data) {
          console.error('tshark error: ', data);
        });

        tshark.on('exit', function (code) {
          console.log('tshark exited with code: ', code);
        });


        //Pass to tshark
        // var streamChild = exec("tshark -C node-tshark -r " + tempName + " -x -V > " + tempName.substring(0, tempName.length - 5) + ".tshark", function(err, stdout, stderr) {
        //   if(err) {
        //     console.log('There was an error running tshark on the packet');
        //     self.emit('error', err);
        //     throw err;
        //   }
        //   //Delete .pcap file
        //   // fs.unlink(tempName, function(err) {
        //   fs.unlink(pathToPacket, function(err) {
        //     if(err) {
        //       console.log('There was an error deleting the file');
        //       self.emit('error', err);
        //       throw err;
        //     }
        //     console.log('stdout: ', stdout);
        //     self.emit('data', stdout);
        //   });
        // });
      });

      function writeGlobalHeader (b) {
        // Magic Number
        b.writeUInt32LE(magicNumber, 0);
        // Major Version Number
        b.writeUInt16LE(majorVersion, 4);
        // Minor Version Number
        b.writeUInt16LE(minorVersion, 6);
        // GMT
        b.writeInt32LE(gmtOffset, 8);
        // Accuracy of Timestamps
        b.writeUInt32LE(timestampAccuracy, 12);
        // Max length of captured packets
        b.writeUInt32LE(snapshotLength, 16);
        // Data Link type
        b.writeUInt32LE(linkLayerType, 20);
      }

      function writePacketHeader (b) {
        // Timestamp - seconds
        b.writeUInt32LE(packet.header.timestampSeconds, 24);
        // Timestamp - microseconds
        b.writeUInt32LE(packet.header.timestampMicroseconds, 28);
        // Number of octets of packet saved in file
        b.writeUInt32LE(packet.header.capturedLength, 32);
        // Actual length of packet
        b.writeUInt32LE(packet.header.originalLength, 36);
      }

    });
  });

  parser.on('end', function () {
    // Do end-y type things.
    console.log('parser on end!');
  });



};
//Function name is subject to change, but I needed a placeholder
var fileShark = function (file, self) {
    var baseName = file.substring(0, file.length - 5); //Remove .pcap
    var fileChild = exec("tshark -C node-tshark -r " + file + " -x -V > " + baseName + ".tshark", function(err, stdout, stderr) {
      if(err) {
        self.emit('error', err);
        throw err;
      }
      self.emit('data', stdout);
    });
  };

/*
  Walk traverses a pathname and returns the set of files within.
  Usage: 
    walk(process.env.PWD, function(err, results){
    if (err) throw err;
    console.log(results);
});
*/
var walk = function (dir, end) {
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
  };