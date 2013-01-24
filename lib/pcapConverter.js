'use strict';

var exec = requre('child_process').exec;
var pcapp = require('pcap-parser');
var crypto = require('crypto');
var fs = require('fs');
var events = require("events");
var packetSep = '--------------------------------------------------';
var PcapConverter = module.exports = function() {

};

PcapConverter.prototype.convertFile = function(fileName) {
  // see testData/pcap2tshark.sh for command line options
  fs.stat(fileName, function(err, stats){
    if (err) throw err;
    if (stats.isDirectory()){

    } else {
      var baseName = fileName.substring(0, fileName.length - 5); //Remove .pcap
      var fileChild = exec("tshark -C node-tshark -r #{fileName} -x -V -S #{packetSep} > #{baseName}.tshark",
        function(err, stdout, stderr){
          if (err) throw err;
          events.emit('done');
      });
    }
  });
};

PcapConverter.prototype.convertStream = function(fileName) {
  // see testData/pcap2tshark.sh for command line options
  var baseName = fileName.substring(0, fileName.length - 5);
  //Read stream using pcap parser
  var parser = new pcapp.Parser(fileName);
  parser.on('packet', function(packet){
  //On "packet" event create .pcap file with that packet in it
    var tempName = fileName + '_temp_' + crypto.randomBytes(32).toString('hex') + '.pcap';
    fs.writeFile(tempName, packet, function(err){
      if (err) throw err;
      //Pass to tshark
      var streamChild = exec("tshark -C node-tshark -r #{tempName} -x -V -s #{packetSep} > #{baseName}.tshark",
        function(err, stdout, stderr){
          if (err) {
            console.log('There was an error running tshark on the packet');
            throw err;
          }
          //Delete .pcap file
          fs.unlink(tempName, function(err){
            if (err) {
              console.log('There was an error deleting the file');
              throw err;
            }
            events.emit('done');
          });
        });
    });
  });
};

var walk = function(path, files){

};
