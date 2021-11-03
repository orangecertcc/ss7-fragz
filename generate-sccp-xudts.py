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

from binascii import hexlify, unhexlify
from cStringIO import StringIO
from collections import namedtuple
import sys
from scapy.all import *
from struct import pack, unpack

SccpMsg = namedtuple('SccpMsg', 'type klass handling header mandatory optional')

class Reader:
  def __init__(self, data):
    self.roff = 0
    self.data = data

  def read(self, n):
    avail = self.data[self.roff:self.roff+n]
    self.advance(len(avail))
    return avail

  def seek(self, off):
    self.roff = off

  def advance(self, n):
    self.roff += n


class ShortRead(Exception): pass
class UnknownType(Exception): pass

def pop_u8(f):
  data = f.read(1)
  if len(data) != 1: raise ShortRead()
  return ord(data)

def pop_u16(f):
  data = f.read(2)
  if len(data) != 2: raise ShortRead()
  return unpack('!H', data)[0]

def pop_u32(f):
  data = f.read(4)
  if len(data) != 4: raise ShortRead()
  return unpack('!I', data)[0]


'''
  header, num of mandatory parameters, allows optional
'''
SCCP_TYPES = {
  0x11: (1, 3, True),
  0x09: (0, 3, False),
}

def decode_sccp(data):
  f = Reader(data)

  type = pop_u8(f)
  u = pop_u8(f)
  message_handling = (u>>4)
  klass = (u & 0x0f)

  hdr = ''
  if type in SCCP_TYPES:
    (header, n_mandatory, use_optional) = SCCP_TYPES[type]

    hdr = f.read(header)

    mandatory_offsets = []
    for i in range(n_mandatory):
      u = pop_u8(f)
      mandatory_offsets.append(f.roff + u - 1)

    if use_optional:
      start_of_optional = f.roff + pop_u8(f)
  else:
    raise UnknownType(type)

  mandatory_parameters = []
  for mp in mandatory_offsets:
    f.seek(mp)

    size = pop_u8(f)
    value = f.read(size)
    assert(len(value) == size)
  
    mandatory_parameters.append(value)

  optional_parameters = []
  if use_optional:
    f.seek(start_of_optional)
    while True:
      parameter_name = pop_u8(f)
      if parameter_name == 0: break
      size = pop_u8(f)
      value = f.read(size)
      assert(len(value) == size)
      optional_parameters.append(value)

  return SccpMsg(type, klass, message_handling, hdr, mandatory_parameters, optional_parameters)



def fragment_sccp(called, calling,
  data, fragsize=12):
  chunks = []
  for o in range(0, len(data), fragsize):
    chunks.append(data[o:o+fragsize])

  for i in range(len(chunks)):
    chunk = chunks[i]
    f = StringIO()
    f.write(pack('!BBBBBBB',
      0x11, # XUDT
      0x01, # handling / class
      0x0c, # hop counter
      4, # first mandatory variable parameter is always at 4
      4+len(called), # second mandatory variable parameter
      4+len(called)+len(calling), # third mandatory variable parameter
      4+len(called)+len(calling)+len(chunk)
    ))

    if i == 0: first_segment = 1
    else: first_segment = 0
    remaining = len(chunks)-1-i

    segmentation = pack('!B', ((first_segment<<7) + (1<<6) + remaining)) + '\xfa\xca\xde'

    f.write(pack('!B', len(called)) + called)
    f.write(pack('!B', len(calling)) + calling)
    f.write(pack('!B', len(chunk)) + chunk)
    f.write(pack('!BB', 0x10, len(segmentation)) + segmentation)
    f.write('\x00')

    yield f.getvalue()


def decode_segment(chunk):
  segmentation = chunk.optional[0]
  u = ord(segmentation[0])
  first = u >> 7
  klass = (u >> 6) & 0x01
  remaining = u & 0x0f
  local_ref = reduce(lambda x,y: x + (y<<8), map(ord, segmentation[1:]))
  return (first, klass, remaining, local_ref)

def reassemble(chunks):
  assert(all(len(c.optional) == 1 for c in chunks))
  segments = [(decode_segment(c), c) for c in chunks]

  # ensure the same local reference is spread across all fragments
  local_ref = None
  for s in segments:
    if local_ref is None: local_ref = s[0][3]
    assert(s[0][3] == local_ref)

  segments = sorted(segments, key=lambda x: x[0][2], reverse=True)

  reassembled = ''
  for s in segments:
    reassembled += s[1].mandatory[2]
  return reassembled


def hexdump(data):
  for i in range(0, len(data), 8):
    sys.stdout.write('%04x  ' % i)
    for j in range(i, min([i+8, len(data)])):
      sys.stdout.write('%02x ' % ord(data[j]))
    print('')

'''
reassembled = reassemble([decode(c) for c in chunks[0:2]])
hexdump(reassembled)

hexdump(decode(chunks[2]).mandatory[2])
'''

M3UA = namedtuple('M3UA', 'version klass type')
SS7 = namedtuple('SS7', 'opc dpc si ni mp sls')

class UnhandledVariant(Exception): pass

def decode_m3ua(f):
  version = pop_u8(f)
  if version != 1: raise UnhandledVariant(version)
  reserved = pop_u8(f)
  if reserved != 0: raise UnhandledVariant(reserved)
  klass = pop_u8(f)
  if klass != 1: raise UnhandledVariant(klass)
  type = pop_u8(f)
  if type != 1: raise UnhandledVariant(type)

  length = pop_u32(f)

  left = length - 8
  data = f.read(left)
  assert(len(data) == left)

  g = Reader(data)

  while True:
    tag = pop_u16(g)
    if tag == 0x210: break
    length = pop_u16(g)
    g.read(length-4)

  if tag != 0x210: return

  length = pop_u16(g)

  opc = pop_u32(g)
  dpc = pop_u32(g)
  si = pop_u8(g)
  ni = pop_u8(g)
  mp = pop_u8(g)
  sls = pop_u8(g)

  ss7 = SS7(opc, dpc, si, ni, mp, sls)

  data = g.read(length-16)
  assert(len(data) == length-16)

  sccp = decode_sccp(data)

  return (M3UA(version, klass, type), ss7, sccp)


def encode_m3ua(m3ua, ss7, sccp):
  f = StringIO()

  f.write(pack('!BBBBIHH', m3ua.version, 0, m3ua.klass, m3ua.type, len(sccp)+16+8,
    0x210, len(sccp)+16))
  f.write(pack('!IIBBBB', ss7.opc, ss7.dpc, ss7.si, ss7.ni, ss7.mp, ss7.sls))
  f.write(sccp)

  return f.getvalue()



def sccp_segment(pkt, fragsize=12):
  # scapy does not support M3UA / SCCP
  data = pkt[SCTPChunkData].data

  f = Reader(data)
  (m3ua, ss7, sccp) = decode_m3ua(f)
  # we require an SCCP UDT containing an upper TCAP to segment
  assert(sccp.type == 0x09) # fragment UDT only
  called = sccp.mandatory[0]
  calling = sccp.mandatory[1]
  tcap = sccp.mandatory[2]

  tsn = pkt[SCTPChunkData].tsn
  stream_seq = pkt[SCTPChunkData].stream_seq

  for xudt in fragment_sccp(called, calling, tcap):
    data = encode_m3ua(m3ua, ss7, xudt)

    new_pkt = pkt.copy()

    new_pkt[IP].len = None
    new_pkt[IP].chksum = None

    new_pkt[SCTP].chksum = None

    new_pkt[SCTPChunkData].tsn = tsn
    tsn += 1
    tsn &= 0xffffffff

    new_pkt[SCTPChunkData].stream_seq = stream_seq
    stream_seq += 1
    stream_seq &= 0xffff

    new_pkt[SCTPChunkData].data = data
    new_pkt[SCTPChunkData].len = None

    yield new_pkt


if __name__ == '__main__':
  import argparse

  parser = argparse.ArgumentParser()
  parser.add_argument('input', help='input filename, expected to a pcap file, containing a single packet containing IP/SCTP/M3UA/SCCP UDT message')
  parser.add_argument('output', help='output filename')
  args = parser.parse_args()

  pkts = rdpcap(args.input)
  assert(len(pkts) == 1)
  pkt = pkts[0]
  assert(IP in pkt)
  assert(SCTP in pkt)
  assert(SCTPChunkData in pkt)

  pkts = sccp_segment(pkt)

  wrpcap(args.output, pkts)
