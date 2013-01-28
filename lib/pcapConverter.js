'use strict';

var exec = require('child_process').exec;
var pcapp = require('pcap-parser');
var crypto = require('crypto');
var util = require("util");
var events = require("events");
var fs = require('fs');
var PcapConverter = module.exports = function() {
  events.EventEmitter.call(this);
};
util.inherits(PcapConverter, events.EventEmitter);

PcapConverter.prototype.convertFile = function(fileName) {
  var self = this;
  // see testData/pcap2tshark.sh for command line options
  fs.stat(fileName, function(err, stats){
    if (err) throw err;
    if (stats.isDirectory()){
      walk(fileName, function(err, results){
        results.forEach(function(file){
          fileShark(file, self);
        });
      });
    } else {
      fileShark(fileName, self);
    }
  });
};

PcapConverter.prototype.convertStream = function(fileName) {
  var self = this;
  // see testData/pcap2tshark.sh for command line options
  var baseName = fileName.path.substring(0, fileName.path.length - 5);
  console.log(fileName.path);
  //Read stream using pcap parser
  var parser = pcapp.parse(fileName.path);
  parser.on('packet', function(packet){
  //On "packet" event create .pcap file with that packet in it
    var tempName = baseName + '_temp_' + crypto.randomBytes(32).toString('hex') + '.pcap';
    console.log(packet.data);
    var packetBuf = new Buffer(packet.data, 'hex');
    fs.writeFile(tempName, packetBuf, function(err){
      if (err) throw err;
      //Pass to tshark
      var streamChild = exec("tshark -C node-tshark -r " + tempName + " -x -V > " + tempName.substring(0, tempName.length - 5) +".tshark",
        function(err, stdout, stderr){
          if (err) {
            console.log('There was an error running tshark on the packet');
            self.emit('error', err);
            throw err;
          }
          //Delete .pcap file
          fs.unlink(tempName, function(err){
            if (err) {
              console.log('There was an error deleting the file');
              self.emit('error', err);
              throw err;
            }
            self.emit('data', stdout);
          });
        });
    });
  });
  self.emit('done');
};
//Function name is subject to change, but I needed a placeholder
var fileShark = function(file, self){
  var baseName = file.substring(0, file.length - 5); //Remove .pcap
  var fileChild = exec("tshark -C node-tshark -r " + file + " -x -V > " + baseName + ".tshark",
    function(err, stdout, stderr){
      if (err) {
        self.emit('error', err);
        throw err;
      }
      self.emit('data', stdout);
      self.emit('done');
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
