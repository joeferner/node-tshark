'use strict';
var assert = require('assert');
var tshark = require('../');
var path = require('path');
var fs = require('fs');

var testDataPath = path.resolve(__dirname, '../testData');

module.exports = {
  "convert pcap file to tshark": function(test) {
    var errOccurred = false;
    var madeFile = false;
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.convertFile(path.resolve(testDataPath, 'http.pcap'));
    pcapConverter.on('error', function(err){
      errOccurred = true;
      console.log("@@@@@@@@@ There was an error");
      return test.fail(err);
    });
    pcapConverter.on('data', function(data) {
      //test.fail('test that data is correct');
      //Test that the file is created correctly
      fs.open(path.resolve(testDataPath, 'http.tshark'), 'r', function(err, fd){
        if (err) 
          throw err;
        else {
          return test.done();
        }
      });
    });
  },

  "convert pcap stream tshark": function(test) {
    var errOccurred = false;
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.convertStream(fs.createReadStream(path.resolve(testDataPath, 'http.pcap')));
    pcapConverter.on('error', function(err){
      errOccurred = true;
      return test.fail(err);
    });
    pcapConverter.on('data', function(data) {
      fs.open(path.resolve(testDataPath, 'http.tshark'), 'r', function(err, fd){
        if (!err) test.done();
      });
    });
  },

  "convert pcap file to tshark read stream": function(test) {
    var errOccurred = false;
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.createStream(path.resolve(testDataPath, 'http.pcap')).pipe(process.stdout);
    // pcapConverter.createStream(path.resolve(testDataPath, 'ethereal.com.pcap'));

    // pcapConverter.on('error', function(err){
    //   errOccurred = true;
    //   return test.fail(err);
    // });
    // pcapConverter.on('data', function(data) {
    //   fs.open(path.resolve(testDataPath, 'http.tshark'), 'r', function(err, fd){
    //     if (!err) test.done();
    //   });
    // });
  }
};
