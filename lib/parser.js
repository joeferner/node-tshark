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
      //Get Request URI
      if (m = line.match(/Request URI:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.uri = m[1];
        return;
      }
      //Get Status Code
      if (m = line.match(/Status Code:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.status_code = m[1];
        return;
      }
      //Get Response Phrase
      if (m = line.match(/Response Phrase:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.response_phrase = m[1];
        return;
      }
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
      if (m = line.match(/Host:(.*)$/)){
        //Strip return character and newline character
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.host = m[1];
        return;
      }
      //Get User-Agent
      if (m = line.match(/User-Agent:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.user_agent = m[1];
        return;
      }
      //Get Accepted Languages
      if (m = line.match(/Accept-Language:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.languages = m[1];
        return;
      }
      //Get Accepted Encodings
      if (m = line.match(/Accept-Encoding:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.encoding = m[1];
        return;
      }
      //Get Accepted Charset
      if (m = line.match(/Accept-Charset:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.charset = m[1];
        return;
      }
      //Get Keep-Alive
      if (m = line.match(/Keep-Alive:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
          if (temp !== '') 
            m[1] = temp; 
        result.keep_alive = m[1];
        return;
      }
      //Get Connection
      if (m = line.match(/Connection:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.connection = m[1];
        return;
      }
      //Get Referer
      if (m = line.match(/Referer:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
          if (temp !== '') 
            m[1] = temp; 
        result.referer = m[1];
        return;
      }
      //Get Date
      if (m = line.match(/Date:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.date = m[1];
        return;
      }
      //Get Server
      if (m = line.match(/Server:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.server = m[1];
        return;
      }
      //Get Last-Modified
      if (m = line.match(/Last-Modified:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.last_modified = m[1];
        return;
      }
      //Get ETag
      if (m = line.match(/ETag:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.etag = m[1];
        return;
      }
      //Get Accept-Ranges
      if (m = line.match(/Accept-Ranges(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.accept_ranges = m[1];
        return;
      }
      //Get Content-Length
      if (m = line.match(/Content-Length:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.content_length = m[1];
        return;
      }
      //Get Content-type
      if (m = line.match(/Content-Type:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.content_type = m[1];
        return;
      }
      //Get P3P
      if (m = line.match(/P3P:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.p3p = m[1];
        return;
      }
      if (m = line.match(/Cache-control:(.*)$/)){
        var temp = removeCarriageReturns(m[1]);
        if (temp !== '') 
          m[1] = temp; 
        result.cache_control = m[1];
      }
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
var removeCarriageReturns = function(line){
  var result = '';
  var temp  = line.indexOf("\\r\\n"); 
  if (temp > 0){
     result = line.substring(0, temp);
  }
  return result;
}
