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
    if stats.isDirectory(){
      walk(fileName, function(err, results){
        results.forEach(function(file){
          fileShark(file);
        });
      });
    } else {
      fileShark(fileName);
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
//Function name is subject to change, but I needed a placeholder
var fileShark = function(file){
  var baseName = file.substring(0, file.length - 5); //Remove .pcap
  var fileChild = exec("tshark -C node-tshark -r #{file} -x -V -S #{packetSep} > #{baseName}.tshark",
    function(err, stdout, stderr){
      if (err) throw err;
      events.emit('done');
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
var walk = function(dir, end) {
  var results = [];
  fs.readdir(dir, function(err, list) {
    if (err) return end(err);
    var pending = list.length;
    if (!pending) return end(null, results);
    list.forEach(function(file) {
      file = dir + '/' + file;
      fs.stat(file, function(err, stat) {
        if (stat && stat.isDirectory()) {
          walk(file, function(err, res) {
            results = results.concat(res);
            if (!--pending) end(null, results);
          });
        } else {
          if (file.substring(file.length-5, file.length).match('.pcap')){
            results.push(file);
          }
          if (!--pending) end(null, results);
        }
      });
    });
  });
};
