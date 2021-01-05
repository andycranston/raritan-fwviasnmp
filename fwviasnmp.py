#
# @(!--#) @(#) fwviasnmp.py, sversion 0.1.0, fversion 006, 05-january-2021
#
# get the firmware revision of a Raritan PDU via SNMP v2c
#

#
# Help from:
# ---------
#
#    http://www.tcpipguide.com/free/t_SNMPVersion2SNMPv2MessageFormats-3.htm
#

#
# OID for firmware
#
#   .1.3.6.1.4.1.13742.6.3.2.3.1.6.1.1.1
#

#
# SNMPv2c packet sent by iReasoning MIB browser
#
# 30 31 02 01 01 04 06 70 75 62 6C 69 63 A0 24 02
# 04 36 8E D0 50 02 01 00 02 01 00 30 16 30 14 06
# 10 2B 06 01 04 01 EB 2E 06 03 02 03 01 06 01 01
# 01 05 00
#

#
# Break down of the above PDU
#
# SEQUENCE
# |-INTEGER                         - SNMP version (1=SNMPv2c)
# |-STRING                          - Communitituy string
# \-GETREQUESTPDU
#   |-INTEGER                       - Packet ID (4 bytes)
#   |-INTEGER                       - Error status
#   |-INTEGER                       - Error offset
#   \-SEQUENCE
#     \-SEQUENCE
#       |-OID                       - OID for firmware
#       |-NULL                      - Null initial value
#

##############################################################################

#
# imports
#

import sys
import os
import argparse
import random
import socket
import select

##############################################################################

#
# globals
#

DEBUG = False

MAX_PACKET_SIZE = 65536

fwversion = ''

##############################################################################

def showpacket(bytes, prefix):
    bpr = 16              # bpr is Bytes Per Row
    
    numbytes = len(bytes)

    if numbytes == 0:
        print('{} <empty packet>'.format(prefix))
    else:
        i = 0
        
        while i < numbytes:
            if (i % bpr) == 0:
                print("{} {:04d} :".format(prefix, i), sep='', end='')
                chars = ''
            
            c = bytes[i]
            
            if (c < 32) or (c > 126):
                c = '?'
            else:
                c = chr(c)
            
            chars += c

            print(" {:02X}".format(bytes[i]), sep='', end='')

            if ((i + 1) % bpr) == 0:
                print('    {}'.format(chars))

            i = i + 1

    if (numbytes % bpr) != 0:
        print('{}    {}'.format(' ' * (3 * (bpr - (numbytes % bpr))), chars))

    return

##############################################################################

def lenint(n):
    if n <= 127:
        return 1
    elif (n >= 128) and (n <= 255):
        return 2
    elif (n >= 256) and (n <= 65535):
        return 3
    elif (n >= 65536) and (n <= 16777215):
        return 4
    else:
        return 5

##############################################################################

def dt_null():
    b = bytearray(2)
    
    b[0] = 0x05
    b[1] = 0
    
    return b

##############################################################################

def dt_object_identifier(oidbytes):
    b = bytearray(2)
    
    b[0] = 0x06
    b[1] = len(oidbytes)
    
    return b + oidbytes

##############################################################################

def dt_sequence(sequencebytes):
    b = bytearray(2)
    
    b[0] = 0x30
    b[1] = len(sequencebytes)
    
    return b + sequencebytes

##############################################################################

def dt_getrequest_pdu(getrequestbytes):
    b = bytearray(2)
    
    b[0] = 0xA0
    b[1] = len(getrequestbytes)
    
    return b + getrequestbytes

##############################################################################

def dt_integer(n, w):
    
    b = bytearray(w + 2)
    
    b[0] = 0x02
    b[1] = w
    
    for i in range((w-1), -1, -1):
        b[i+2] = n & 0xFF
        
        n = (n >> 8)
    
    return b

##############################################################################

def dt_byte(b):
    return dt_integer(b, 1)

##############################################################################

def dt_word(w):
    return dt_integer(w, 2)

##############################################################################

def dt_dword(w):
    return dt_integer(w, 4)

##############################################################################

def dt_string(s):
    b = bytearray(2 + len(s))
    
    b[0] = 0x04
    b[1] = len(s)
    
    for i in range(0, len(s)):
        b[i+2] = ord(s[i])
    
    return b

##############################################################################


def fwoidbytes():
    #         1 3   6     1     4     1     13742       6     3     2     3     1     6     1     1     1       
    bytes = [ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xEB, 0x2E, 0x06, 0x03, 0x02, 0x03, 0x01, 0x06, 0x01, 0x01, 0x01 ]
    
    oid = bytearray(len(bytes))
    
    for i in range(0, len(bytes)):
        oid[i] = bytes[i]
    
    return oid

##############################################################################

def packetdecode(packet, level):
    global DEBUG
    global fwversion
    
    plen = len(packet)
    
    i = 0
    
    while True:
        if i == plen:
            return 0
            
        dt = packet[i]
        i += 1
        
        if i == plen:
            return -1
        
        lendata = packet[i]        
        i += 1
    
        if lendata > 127:
            if DEBUG:
                print('Length byte exceeds 127 bytes')
            return -2
        
        if DEBUG:
            print('  Level: 0x{:02X}   Datatype: 0x{:02X}   Length: 0x{:02X}'.format(level, dt, lendata))
        
        if (i + lendata) > plen:
            return -3
        
        if dt in [ 0x30, 0xA2 ]:
            retcode = packetdecode(packet[i:i+lendata], level + 1)
            if retcode != 0:
                return retcode
        else:
            if DEBUG:
                showpacket(packet[i:i+lendata], '=')
            if (level == 4) and(dt == 0x04):
                fwversion = packet[i:i+lendata].decode('utf-8')
        i = i + lendata
    
    return 0
    
##############################################################################

def querypdu(hostname, portnumber, readstring, timeout):
    global DEBUG
    global fwversion
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    packetid = random.randint(0, 0xFFFFFFFF)

    print('Querying PDU {} with a packet id 0x{:08X}'.format(hostname, packetid))

    outpacket = bytearray(0)
    outpacket = dt_null() + outpacket
    outpacket = dt_object_identifier(fwoidbytes()) + outpacket
    outpacket = dt_sequence(outpacket)
    outpacket = dt_sequence(outpacket)
    outpacket = dt_byte(0) + outpacket
    outpacket = dt_byte(0) + outpacket
    outpacket = dt_dword(packetid) + outpacket
    outpacket = dt_getrequest_pdu(outpacket)    
    outpacket = dt_string(readstring) + outpacket
    outpacket = dt_byte(1) + outpacket
    outpacket = dt_sequence(outpacket)

    if DEBUG:    
        showpacket(outpacket, '>')
    
    try:
        sock.sendto(outpacket, (hostname, portnumber))
    except socket.gaierror:
        fwversion = '*** Hostname lookup error ***'
        return
    
    ready, dummy1, dummy2 = select.select([sock], [], [], timeout)
    
    if len(ready) == 0:
        fwversion = '*** Timeout ***'
        return
        
    try:
        inpacket, server = sock.recvfrom(MAX_PACKET_SIZE)
    except ConnectionResetError:
        fwversion = '*** Connection Reset Error ***'
        return
       
    if DEBUG: 
        showpacket(inpacket, '<')

    retcode = packetdecode(inpacket, 0)
    
    if retcode != 0:
        fwversion = 'Badly formed response packet - retcode={}'.format(retcode)    
    elif fwversion == '':
        fwversion = 'Unable to get firmware version via SNMP'

    return

##############################################################################

def expandips(ip):
    octets = ip.split('.')
    
    if len(octets) != 4:
        return [ip]
    
    lastoctet = octets[3]
    
    if lastoctet.find('-') == -1:
        return [ip]

    startend = lastoctet.split('-')
    
    if len(startend) != 2:
        return [ip]
    
    try:
        start = int(startend[0])
        end = int(startend[1])
    except ValueError:
        return [ip]

    iplist = []
        
    while start <= end:
        iplist.append("{}.{}.{}.{}".format(octets[0], octets[1], octets[2], start))
        start += 1

    return iplist

##############################################################################

def queryallpdus(hostfile, csvfile, portnumber, readstring, timeout):
    global fwversion
    
    for line in hostfile:
        line = line.strip()
        
        if line == '':
            continue
            
        if line[0] == '#':
            continue
        
        words = line.split()

        for word in words:
             hostnames = expandips(word)
             
             for hostname in hostnames:        
                fwversion = ''
                querypdu(hostname, portnumber, readstring, timeout)
                print(fwversion)
                print('"{}","{}"'.format(hostname, fwversion), file=csvfile)
                csvfile.flush()
    
    return

##############################################################################

def main():
    global progname
    global DEBUG
    
    parser = argparse.ArgumentParser()
        
    parser.add_argument('--hostlist',
                        help='file containing list of PDU hostnames/IP addresses',
                        default='hostlist.txt')
                        
    parser.add_argument('--csvfile',
                        help='file containing PDU names/IP addresses',
                        default='fwreport.csv')
                        
    parser.add_argument('--read',
                        help='read community string',
                        default='public')
                        
    parser.add_argument('--port',
                        help='port number',
                        type=int,
                        default=161)
                        
    parser.add_argument('--timeout',
                        help='port number',
                        type=float,
                        default=3.0)

    parser.add_argument('--debug',
                        help='output additional information for debugging',
                        action='store_true')

    args = parser.parse_args()
    
    if args.debug:
        DEBUG = True
        
    try:
        hostfile = open(args.hostlist, 'r')
    except IOError:
        print('{}: unable to open PDU host list file "{}" for reading'.format(progname, args.hostlist), file=sys.stderr)
        return 1

    try:
        csvfile = open(args.csvfile, 'w')
    except IOError:
        print('{}: unable to open CSV firmware file "{}" for writing'.format(progname, args.csvfile), file=sys.stderr)
        return 1
                
    queryallpdus(hostfile, csvfile, args.port, args.read, args.timeout)    
    
    csvfile.flush()
    
    csvfile.close()
    
    hostfile.close()

    return 0

##############################################################################

progname = os.path.basename(sys.argv[0])

sys.exit(main())

# end of file
