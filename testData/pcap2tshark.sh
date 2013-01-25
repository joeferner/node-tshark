#!/bin/bash

echo ""
echo "Make sure you create a configuration profile in WireShark and set the following options:"
echo "  - Disable relative TCP sequence numbers"
echo ""

for f in *.pcap; do
  tshark -C node-tshark -r $f -x -V > `basename ${f%.*}`.tshark
done
