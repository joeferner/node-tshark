'use strict';

var tshark = require('../');
var path = require('path');
var fs = require('fs');

var testDataPath = path.resolve(__dirname, '../testData');

module.exports = {
  "convert pcap file to tshark": function(test) {
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.convertFile(path.resolve(testDataPath, 'http.pcap'));
    pcapConverter.on('data', function(data) {
      test.fail('test that data is correct');
    });
    pcapConverter.on('done', function() {
      test.done();
    });
  },

  "convert pcap stream tshark": function(test) {
    var pcapConverter = new tshark.PcapConverter();
    pcapConverter.convertStream(fs.createReadStream(path.resolve(testDataPath, 'http.pcap')));
    pcapConverter.on('data', function(data) {
      test.fail('test that data is correct');
    });
    pcapConverter.on('done', function() {
      test.done();
    });
  }
};
