'use strict';

var tshark = require('../');
var path = require('path');

var testDataPath = path.resolve(__dirname, '../testData');

module.exports = {
  "parse http.pcap": function(test) {
    var errorOccured = false;
    var foundHttpRequest = false;
    var parser = new tshark.Parser();
    parser.parseFile(path.resolve(testDataPath, 'http.tshark'));
    parser.on('packet', function(packet) {
      if (errorOccured) {
        return 0;
      }
      //console.log(packet);
      if (!packet.tcp || packet.tcp.streamIndex != 0 || packet.tcp.destPort != 80 || packet.tcp.data.length == 0) {
        return 0;
      }
      var request = packet.tcp.data.toString();
      test.ok(request.indexOf('GET /download.html HTTP/1.1') >= 0);
      test.ok(request.indexOf('Host: www.ethereal.com') >= 0);
      foundHttpRequest = true;
      return 0;
    });
    parser.on('error', function(err) {
      errorOccured = true;
      return test.done(err);
    });
    parser.on('end', function() {
      if (!foundHttpRequest) {
        return test.fail("did not find HTTP request");
      }
      if (!errorOccured) {
        return test.done();
      }
      return 0;
    });
  },

  "parse httpSplit.pcap": function(test) {
    var errorOccured = false;
    var endCount = 0;
    var packetCount = 0;
    var parser = new tshark.Parser();
    parser.parseFile(path.resolve(testDataPath, 'httpSplit_00000_20040513061707.tshark'));
    parser.parseFile(path.resolve(testDataPath, 'httpSplit_00001_20040513061708.tshark'));
    parser.parseFile(path.resolve(testDataPath, 'httpSplit_00002_20040513061708.tshark'));
    parser.parseFile(path.resolve(testDataPath, 'httpSplit_00003_20040513061708.tshark'));
    parser.on('packet', function(packet) {
      if (errorOccured) {
        return 0;
      }
      //console.log(packet);
      packetCount++;
      return 0;
    });
    parser.on('error', function(err) {
      errorOccured = true;
      return test.done(err);
    });
    parser.on('end', function() {
      endCount++;
      if (!errorOccured && endCount == 4) {
        test.equals(4, packetCount);
        return test.done();
      }
      return 0;
    });
  }
};
