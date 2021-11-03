#!/usr/bin/env python2.7

'''
MIT License
Copyright (c) 2019 Orange CERT-CC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

from scapy.all import *

def sctp_segment(pkt, fragsize=42):
  '''harder: clone packets and generate segmentation at SCTP level.
As a bonus, it will evade equipements performing IP reassembly.'''
  assert(IP in pkt)
  assert(SCTP in pkt)
  assert(SCTPChunkData in pkt)

  data_chunk = pkt[SCTPChunkData]
  assert(data_chunk.beginning == 1)
  assert(data_chunk.ending == 1)
  total_length = data_chunk.len
  data = data_chunk.data
  tsn = data_chunk.tsn

  for o in range(0, len(data), fragsize):
    new_pkt = pkt.copy()

    new_pkt[IP].len = None
    new_pkt[IP].chksum = None

    new_pkt[SCTP].chksum = None

    new_pkt[SCTPChunkData].beginning = 0
    new_pkt[SCTPChunkData].ending = 0
    new_pkt[SCTPChunkData].data = data[o:o+fragsize]
    new_pkt[SCTPChunkData].len = None
    new_pkt[SCTPChunkData].tsn = tsn + o//fragsize

    if o == 0:
      new_pkt[SCTPChunkData].beginning = 1
    elif o + fragsize >= len(data):
      new_pkt[SCTPChunkData].ending = 1
      new_pkt[SCTPChunkData].data = data[o:]

    yield new_pkt


if __name__ == '__main__':
  import argparse

  parser = argparse.ArgumentParser()
  parser.add_argument('input', help='input filename, expected to a pcap file, containing a single packet containing IP/SCTP/M3UA/SCCP layers')
  parser.add_argument('output', help='output filename')
  args = parser.parse_args()

  pkts = rdpcap(args.input)
  assert(len(pkts) == 1)
  pkt = pkts[0]
  assert(IP in pkt)
  assert(SCTP in pkt)
  assert(SCTPChunkData in pkt)

  pkts = sctp_segment(pkt)

  wrpcap(args.output, pkts)
