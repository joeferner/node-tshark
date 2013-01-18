'use strict';

var tshark = require('../');
var path = require('path');

var testDataPath = path.resolve(__dirname, '../testData');

module.exports = {
  "parse http.pcap": function(test) {
    var errorOccured = false;
    var parser = new tshark.Parser();
    parser.parseFile(path.resolve(testDataPath, 'http.tshark'));
    parser.on('packet', function(packet) {
      if (errorOccured) {
        return 0;
      }
      if (!packet.tcp || packet.tcp.streamIndex != 0 || packet.tcp.destPort != 80 || packet.tcp.data.length == 0) {
        return 0;
      }
      var request = packet.tcp.data.toString();
      test.ok(request.indexOf('GET /download.html HTTP/1.1') >= 0);
      test.ok(request.indexOf('Host: www.ethereal.com') >= 0);
      return 0;
    });
    parser.on('error', function(err) {
      errorOccured = true;
      return test.done(err);
    });
    parser.on('end', function() {
      if (!errorOccured) {
        return test.done();
      }
      return 0;
    });
  }
};
