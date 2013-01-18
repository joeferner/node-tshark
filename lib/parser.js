'use strict';

var fs = require('fs');
var lazy = require('lazy');
var util = require("util");
var events = require("events");

var Parser = module.exports = function(opts) {
  this.opts = opts || {};
  this.opts.packetSeperator = this.opts.packetSeperator || '--------------------------------------------------'
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
      self.emit('end');
    })
    .lines
    .map(String)
    .forEach(function(line) {
      if (line.trim().length == 0) {
        line = line.trim();
      }
      if (line == self.opts.packetSeperator) {
        try {
          var packet = Parser.parsePacketLines(packetLines);
          self.emit('packet', packet);
        } catch (e) {
          self.emit('error', e);
          return null;
        }
        packetLines = [];
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

      if (m = line.match(/Source port:.*\(([0-9]*)/)) {
        result.sourcePort = parseInt(m[1]);
        return;
      }

      if (m = line.match(/Destination port:.*\(([0-9]*)/)) {
        result.destPort = parseInt(m[1]);
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
