#!/bin/bash

echo ""
echo "Make sure you create a configuration profile in WireShark and set the following options:"
echo "  - Disable relative TCP sequence numbers"
echo ""

PACKET_SEP="--------------------------------------------------"

for f in *.pcap; do
  tshark -C node-tshark -r $f -x -V -S $PACKET_SEP > `basename ${f%.*}`.tshark
done
