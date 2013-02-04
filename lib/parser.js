'use strict';

var fs = require('fs');
var lazy = require('lazy');
var util = require("util");
var events = require("events");

var Parser = module.exports = function(opts) {
  this.opts = opts || {};
  events.EventEmitter.call(this);
};
util.inherits(Parser, events.EventEmitter);

Parser.prototype.parseFile = function(fileName) {
  return this.parseStream(fs.createReadStream(fileName));
};

Parser.prototype.parseStream = function(stream) {
  var self = this;
  var packetLines = [];
  return lazy(stream)
    .on('end', function() {
      var packet = Parser.parsePacketLines(packetLines);
      self.emit('packet', packet);
      self.emit('end');
    })
    .lines
    .map(String)
    .forEach(function(line) {
      if (line.trim().length == 0) {
        line = line.trim();
      }
      var m = line.match(/Frame \d+:/g);
      if (m && packetLines.length > 0) {
        try {
          var packet = Parser.parsePacketLines(packetLines);
          packetLines = [line];
          self.emit('packet', packet);
        } catch (e) {
          self.emit('error', e);
          return null;
        }
      } else {
        packetLines.push(line);
      }
    });
};

Parser.parsePacketLines = function(lines) {
  try {
    var m;
    var linesBySection = {};
    var dataType = 'frame';
    var section = 'frame';
    var packet = {
    };
    lines.forEach(function(line, i) {
      //console.log(line);
      if (i == 0) {
        packet.frameSummary = Parser.parseFrameSummaryLine(line);
        packet.data = new Buffer(packet.frameSummary.bytesCaptured);
        return;
      }

      // handle multiple data sections: Frame, Reassembled TCP, Uncompressed
      if (m = line.match(/^(.*) \([0-9]* bytes\):$/)) {
        dataType = m[1].trim().toLocaleLowerCase();
        return;
      }
      if (dataType !== 'frame') {
        return;
      }

      var dataLine = Parser.tryParseDataLine(line);
      if (dataLine) {
        dataLine.data.copy(packet.data, dataLine.address, 0, dataLine.data.length);
        return;
      }

      // handle sections
      if (line.match(/^Ethernet II, .*$/)) {
        section = 'ethernet';
      } else if (line.match(/^Internet Protocol Version .*$/)) {
        section = 'ip';
      } else if (line.match(/^Transmission Control Protocol, .*$/)) {
        section = 'tcp';
      } else if (line.match(/^User Datagram Protocol, .*$/)) {
        section = 'udp';
      } else if (line.match(/^Domain Name System .*$/)) {
        section = 'dns';
      } else if (line.match(/^Hypertext Transfer Protocol$/)) {
        section = 'http';
      }

      linesBySection[section] = linesBySection[section] || [];
      linesBySection[section].push(line);
    });

    Object.keys(linesBySection).forEach(function(section) {
      if (Parser.sectionParsers[section]) {
        packet[section] = Parser.sectionParsers[section](linesBySection[section], packet);
      }
    });

    return packet;
  } catch (e) {
    e.lines = lines;
    throw e;
  }
};

Parser.sectionParsers = {
  http: function(lines, packet){  
    //console.log(lines);
    var m;
    var result = {};
    lines.forEach(function(line){
      var temp = null;

      //Get Request URI
      httpParseTemplate(line, result, RegExp('Request URI:(.*)$'), 'uri');
      //Get Status Code
      httpParseTemplate(line, result, RegExp('Status Code:(.*)$'), 'status_code');
      //Get Response Phrase
      httpParseTemplate(line, result, RegExp('Response Phrase:(.*)$'), 'response_phrase');
      //Get Request Method field
      if (m = line.match(/Request Method:(.*)$/)){
        result.method = m[1];
        return;
      }
      //Get Request Version
      if (m = line.match(/Request Version:(.*)$/)){
        result.version = m[1];
        return;
      }
      //Get Host name
      httpParseTemplate(line, result, RegExp('Host:(.*)$'), 'host');
      //Get User-Agent
      httpParseTemplate(line, result, RegExp('User-Agent:(.*)$'), 'user_agent');
      //Get Accepted Languages
      httpParseTemplate(line, result, RegExp('Accept-Language:(.*)$'), 'languages');
      //Get Accepted Encodings
      httpParseTemplate(line, result, RegExp('Accept-Encoding:(.*)$'), 'encoding');
      //Get Accepted Charset
      httpParseTemplate(line, result, RegExp('Accept-Charset:(.*)$'), 'charset');
      //Get Keep-Alive
      httpParseTemplate(line, result, RegExp('Keep-Alive:(.*)$'), 'keep_alive');
      //Get Connection
      httpParseTemplate(line, result, RegExp('Connection:(.*)$'), 'connection');
      //Get Referer
      httpParseTemplate(line, result, RegExp('Referer:(.*)$'), 'referer');
      //Get Date
      httpParseTemplate(line, result, RegExp('Date:(.*)$'), 'date');
      //Get Server
      httpParseTemplate(line, result, RegExp('Server:(.*)$'), 'server');
      //Get Last-Modified
      httpParseTemplate(line, result, RegExp('Last-Modified:(.*)$'), 'last_modified');
      //Get ETag
      httpParseTemplate(line, result, RegExp('ETag:(.*)$'), 'etag');
      //Get Accept-Ranges
      httpParseTemplate(line, result, RegExp('Accept-Ranges:(.*)$'), 'accept_ranges');
      //Get Content-Length
      httpParseTemplate(line, result, RegExp('Content-Length:(.*)$'), 'content_length');
      //Get Content-type
      httpParseTemplate(line, result, RegExp('Content-Type:(.*)$'), 'content_type');
      //Get P3P
      httpParseTemplate(line, result, RegExp('P3P:(.*)$'), 'p3p');
      //Get Cache-control
      httpParseTemplate(line, result, RegExp('Cache-control:(.*)$'), 'cache_control');
    });
    return result;
  },

  ip: function(lines, packet) {
    //console.log(lines);
    var m;
    var result = {};
    lines.forEach(function(line) {
      if (m = line.match(/Source: ([0-9\.]*)/)) {
        result.source = m[1];
        return;
      }

      if (m = line.match(/Destination: ([0-9\.]*)/)) {
        result.dest = m[1];
        return;
      }
    });
    return result;
  },

  tcp: function(lines, packet) {
    //console.log(lines);
    var m;
    var result = {};
    lines.forEach(function(line, i) {
      if (i == 0 && (m = line.match(/Len: ([0-9]*)/))) {
        result.dataLength = parseInt(m[1]);
        return;
      }

      if (m = line.match(/\[Stream index: ([0-9]*)\]/)) {
        result.streamIndex = parseInt(m[1]);
        return;
      }

      if (m = line.match(/Flags:.*\((.*)\)/)) {
        result.flags = m[1].split(',').map(function(f) { return f.trim(); });
        result.isFIN = result.flags.indexOf('FIN') >= 0;
        result.isACK = result.flags.indexOf('ACK') >= 0;
        result.isPSH = result.flags.indexOf('PSH') >= 0;
        result.isSYN = result.flags.indexOf('SYN') >= 0;
        return;
      }

      if (m = line.match(/Source port:.*\(([0-9]*)\)/)) {
        result.sourcePort = parseInt(m[1]);
        return;
      }

      if (m = line.match(/Destination port:.*\(([0-9]*)\)/)) {
        result.destPort = parseInt(m[1]);
        return;
      }

      if (m = line.match(/Sequence number: ([0-9]*)/)) {
        result.seq = parseInt(m[1]);
        return;
      }

      if (m = line.match(/Acknowledgment number: ([0-9]*)/)) {
        result.ack = parseInt(m[1]);
        return;
      }
    });

    result.data = packet.data.slice(packet.data.length - result.dataLength);

    return result;
  }
};

Parser.tryParseDataLine = function(line) {
  var m = line.match(/^([0-9a-fA-F]+)\s+?([0-9a-fA-F ]+)\s+?.+$/);
  if (!m) {
    return null;
  }
  return {
    address: parseInt(m[1], 16),
    data: new Buffer(m[2].trim().split(' ').map(function(p) { return parseInt(p, 16); }))
  };
};

Parser.parseFrameSummaryLine = function(line) {
  var m = line.match(/Frame (.*): ([0-9]*) bytes on wire \([0-9]* bits\), ([0-9]*) bytes captured \([0-9]* bits\)/);
  if (!m) {
    throw new Error('Could not parse packet.');
  }
  return {
    frame: m[1],
    bytesOnWire: parseInt(m[2]),
    bytesCaptured: parseInt(m[3])
  };
};

//Helper Functions
var removeCarriageReturns = function(line) {
  var result = '';
  var temp  = line.indexOf("\\r\\n"); 
  if (temp > 0){
     result = line.substring(0, temp);
  }
  return result;
}

var httpParseTemplate = function (line, result, regexString, keyName) {
  var m;
  var temp;
  if (m = line.match(regexString)) {
    temp = removeCarriageReturns(m[1]);
    if (temp !== '') {
      m[1] = temp; 
    }
    result[keyName] = m[1];
    return;
  }
}
