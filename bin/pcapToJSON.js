#!/usr/bin/env node
'use strict'

var optimist = require('optimist');
var nodeTshark = require('../');
var fs = require('fs');
var sf = require('sf');
var path = require('path');


var argv = optimist
  .usage('Usage: tag.js [options]')
  .options('in', {
    alias: 'i',
    describe: 'The input file or "-" for stdin.'
  })
  .options('out', {
    alias: 'o',
    describe: 'The output file or "-" for stdout.'
  })
  .alias('help', 'h')
  .alias('h', '?')
  .argv;

if (argv.help) {
  optimist.showHelp();
  process.exit(1);
}

var input;
if (!argv.in || argv.in === '-') {
  input = process.stdin;
} else {
  input = argv.in;
}
var output;
if (!argv.out || argv.out === '-') {
  output = process.stdout;
} else {
  output = argv.out;
}
process.on('uncaughtException', function(err) {
  console.error('uncaughtException', err.stack || err);
});
var testDataPath = path.resolve(__dirname, '../testData');

var metricsFile = path.resolve(testDataPath, 'metrics.log');

markNewConversion();


var pcapConverter = new nodeTshark.PcapConverter({
  maxPacketQueueSize: 100000
});
pcapConverter.convertStream(input);
pcapConverter.on('packet', function(packet) {
  output.write(packet + '\n');
});
pcapConverter.on('end', function() {
  outputMetrics(pcapConverter, function () {
    output.write('end' + '\n');
    process.exit(0);
  });
})

var metricsInterval = setInterval(function() {
  outputMetrics(pcapConverter);
}, 3000);

function outputMetrics(pcapConverter, optionalCallback) {
  var date = new Date();
  var metrics = {
    date: date,
    incomingTotalPacketCount: pcapConverter.metrics.incomingPacketCount.sum,
    incomingPacketRate: pcapConverter.metrics.incomingPacketCount.mean(),
    incomingAvgDataRate: pcapConverter.metrics.incomingData.mean() / 1024.0 / 1024.0 * 8,
    outgoingTotalPacketCount: pcapConverter.metrics.outgoingPacketCount.sum,
    outgoingPacketRate: pcapConverter.metrics.outgoingPacketCount.mean(),
    droppedPacketCount: pcapConverter.metrics.droppedPacketCount.sum,
    outgoingAvgDataRate: pcapConverter.metrics.outgoingData.mean() / 1024.0 / 1024.0 * 8,
    maxPacketQueueSize: pcapConverter.metrics.packetQueue.max,
    avgPacketQueueSize: pcapConverter.metrics.packetQueue.mean(),
    maxTsharkQueueSize: pcapConverter.metrics.tsharkQueue.max,
    avgTsharkQueueSize: pcapConverter.metrics.tsharkQueue.mean(),
    totalTime: new sf.TimeSpan(date - pcapConverter.metrics.startTime)
  };
  var logString = sf(
    "{date}\n"
      + "\tIncoming Total Packets: {incomingTotalPacketCount:#,##0}\n"
      + "\tIncoming Packet Rate: {incomingPacketRate:#,##0} packets/s\n"
      + "\tIncoming Average Data Rate: {incomingAvgDataRate:#,##0.00} Mb/s\n"
      + "\tOutgoing Total Packets: {outgoingTotalPacketCount:#,##0}\n"
      + "\tOutgoing Packet Rate: {outgoingPacketRate:#,##0} packets/s\n"
      + "\tOutgoing Average Data Rate: {outgoingAvgDataRate:#,##0.00} Mb/s\n"
      + "\tAverage Packet Queue Size: {avgPacketQueueSize:#,##0}\n"
      + "\tMaximum Packet Queue Size: {maxPacketQueueSize:#,##0}\n"
      + "\tAverage TShark Queue Size: {avgTsharkQueueSize:#,##0}\n"
      + "\tMaximum TShark Queue Size: {maxTsharkQueueSize:#,##0}\n"
      + "\tDropped Packet Count: {droppedPacketCount:#,##0}\n"
      + "\tTotal Time: {totalTime:h'h' mm'm' ss's'}\n",
    metrics);
  fs.appendFile(metricsFile, logString, function(err) {
    if (err) {
      throw err;
    }
    if (optionalCallback) {
      return optionalCallback();
    }
  });
}

function markNewConversion() {
  var logString = "------------NEW CONVERSION------------\n";
  fs.appendFile(metricsFile, logString, function(err) {
    if (err) {
      throw err;
    }
  });
}


