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
      return test.done(err);
    });
    pcapConverter.on('data', function(data) {
      //test.fail('test that data is correct');
      //Test that the file is created correctly
      fs.open(path.resolve(testDataPath, 'http.tshark'), 'r', function(err, fd){
        if (!err) {
          madeFile = true;
        }
        if (err) throw err;
      });
    });
    pcapConverter.on('done', function() {
      if (!madeFile){
        test.fail('A file was not made');
        return test.done();
      }
      if (!errOccurred)
        console.log("######### Finishing test");
        return test.done();
      return 0;
    });
  },

  "convert pcap stream tshark": function(test) {
    var errOccurred = false;
    var madeFile = false;
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.convertStream(fs.createReadStream(path.resolve(testDataPath, 'http.pcap')));
    pcapConverter.on('error', function(err){
      errOccurred = true;
      return test.done(err);
    });
    pcapConverter.on('data', function(data) {
      fs.open(path.resolve(testDataPath, 'http.tshark'), 'r', function(err, fd){
        if (!err) madeFile = true;
      });
    });
    pcapConverter.on('done', function() {
      if (!madeFile)
        return test.fail('A file was not made');
      if (!errOccurred)
        return test.done();
      return 0;
    });
  }
};
