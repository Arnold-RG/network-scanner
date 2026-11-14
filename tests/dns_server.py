#!/usr/bin/env python3
"""Tiny fake DNS server for the tests (127.0.0.1 only).

Answers every A query with a CNAME (using name compression) followed by two A
records and the AD flag, and returns NXDOMAIN for names starting with "nx-".
It exercises the hand-written DNS parser in lib/NetTools.psm1.
"""
import socket
import struct
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15353
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", port))


def encode(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


while True:
    data, addr = sock.recvfrom(512)
    qid = data[:2]
    # question = everything after the 12-byte header
    question = data[12:]
    labels, i = [], 0
    while question[i] != 0:
        n = question[i]
        labels.append(question[i + 1:i + 1 + n].decode())
        i += n + 1
    qname = ".".join(labels)
    qsection = question[:i + 5]
    if qname.startswith("nx-"):
        hdr = qid + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0)  # QR RD RA, NXDOMAIN
        sock.sendto(hdr + qsection, addr)
        continue
    target = "edge." + qname
    cname = struct.pack(">HHHIH", 0xC00C, 5, 1, 300, len(encode(target))) + encode(target)
    tpos = 12 + len(qsection) + 12          # offset of the CNAME target name
    a1 = struct.pack(">HHHIH", 0xC000 | tpos, 1, 1, 60, 4) + bytes([203, 0, 113, 7])
    a2 = struct.pack(">HHHIH", 0xC000 | tpos, 1, 1, 60, 4) + bytes([203, 0, 113, 8])
    hdr = qid + struct.pack(">HHHHH", 0x81A0, 1, 3, 0, 0)    # QR RD RA AD, 3 answers
    sock.sendto(hdr + qsection + cname + a1 + a2, addr)
