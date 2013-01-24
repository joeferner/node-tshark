'use strict';
var optimist = require('optimist');
var tshark = require('../');

var args = optimist
  .alias('h', 'help')
  .options('file', {
    alias:'f',
    describe: "The file to be parsed."
  })
  .argv;

var parser = new tshark.Parser();

if (args.help) {
  optimist.showHelp();
  return process.exit(-1);
}

parser.parseFile(args.file);
parser.on('packet', function(packet) {

  console.log(packet);
});
parser.on('error', function(err) {
  console.log("error:");  
  process.exit(-1);    
});
parser.on('end', function() {
  process.exit(0);
  return 0;
});



