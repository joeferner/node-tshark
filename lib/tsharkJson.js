'use strict';

var optimist = require('optimist');
var tshark = require('../');
var spawn = require('child_process').spawn;

var argv = optimist
  .options('infile', {
    alias: 'i',
    describe: 'The file to process.'
  })
  .alias('help', 'h')
  .alias('h', '?')
  .argv;

if (argv.help) {
  optimist.showHelp();
  process.exit(1);
}

if (!argv.infile) {
  console.error("You must specify an input file.")
  process.exit(1);
}

var tsharkParser = new tshark.Parser();
var tsharkParams = ['-C', 'node-tshark', '-r', argv.infile, '-x', '-V'];
var tshark = spawn('tshark', tsharkParams);
tsharkParser.parseStream(tshark.stdout);
tsharkParser.on('packet', function(packet) {
  convertBuffersToArrays(packet);
  console.log(JSON.stringify(packet));
});
tsharkParser.on('end', function() {
  return process.exit(0);
});
tshark.stderr.on('data', function(data) {
  if (data.toString().indexOf('gnome-keyring') > 0) {
    return;
  }
  console.error(data.toString());
});
tshark.on('close', function(code) {
  if (code != 0) {
    return process.exit(code);
  }
});

function convertBuffersToArrays(obj) {
  Object.keys(obj).forEach(function(key) {
    var child = obj[key];
    if (child instanceof Buffer) {
      obj[key] = bufferToArray(child);
    } else if (typeof(child) == 'object') {
      convertBuffersToArrays(child);
    }
  });
}

function bufferToArray(buf) {
  var result = [];
  for (var i = 0; i < buf.length; i++) {
    result.push(buf[i]);
  }
  return {
    type: 'buffer',
    data: result
  };
}