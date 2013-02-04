'use strict';
var assert = require('assert');
var tshark = require('../');
var path = require('path');
var fs = require('fs');

var testDataPath = path.resolve(__dirname, '../testData');

module.exports = {
  "convert pcap file to tshark": function(test) {
    var errOccurred = false;
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.convertFile(path.resolve(testDataPath, 'http.pcap'));
    pcapConverter.on('error', function(err) {
      errOccurred = err;
      return test.done(err);
    });
    pcapConverter.on('data', function(data) {
      if (errOccurred) {
        return 0;
      }
      // spot check the results
      test.ok(data.indexOf('http://www.ethereal.com/download.html') > 0, 'Could not find "http://www.ethereal.com/download.html"');
    });
    pcapConverter.on('end', function() {
      if (errOccurred) {
        return 0;
      }
      return test.done();
    });
    return 0;
  },

  "convert pcap stream tshark": function(test) {
    var errOccurred = null;
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.convertStream(fs.createReadStream(path.resolve(testDataPath, 'http.pcap')));
    pcapConverter.on('error', function(err) {
      errOccurred = err;
      return test.done(err);
    });
    pcapConverter.on('data', function(data) {
      if (errOccurred) {
        return;
      }
      fs.open(path.resolve(testDataPath, 'http.tshark'), 'r', function(err, fd) {
      });
    });
    pcapConverter.on('end', function() {
      if (errOccurred) {
        return;
      }
      test.done();
    });
  }
};
