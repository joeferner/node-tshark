'use strict';
//This is used to generate test data from tshark files for using with the tshark reassembler.
//After creating the text, the following alterations need to be performed:
//Global replace on 'new Buffer to new Buffer and global replace on ' \}\n\}); to \}\n\});
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
  var bufferString = packet.tcp.data.toString() || "0";
  bufferString = encodeURI(bufferString);
  packet.tcp.data = "new Buffer(\"" + bufferString + "\")";
  console.log("reassembler.push({\n  ip:", packet.ip, ",");
  console.log("  tcp:", packet.tcp);
  console.log("});\n");
});
parser.on('error', function(err) {
  console.log("error:", err);  
  process.exit(-1);    
});
parser.on('end', function() {
  process.exit(0);
  return 0;
});



