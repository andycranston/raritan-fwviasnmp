# raritan-fwviasnmp

Generate a Raritan PDU firmware version report using SNMP v2c.

## Prerequisites

You will need Python 3 installed.

If a firewall is active then it must be configured to allow IPv4
UDP traffic to flow in and out on port 161.

Your Raritan PDUs must be configured to accept SNMP v2c read requests.

You must know the read community string on each PDU.

## Quick start

Edit the `hostlist.txt` file and put the names and/or IPv4 addresses of the Raritan PDUs
you wish to query to create the firmware version report.  For example:

```
10.1.1.21
px3rack
```

Now run the following command line:

```
python fwviasnmp.py
```

Note: depending on you environment you might need to type:

```
python3 fwviasnmp.py
```

This should produce output similar to:

```
Querying PDU 10.1.1.21 with a packet id 0x0EB39E50
3.6.1.5-46982
Querying PDU px3rack with a packet id 0x13F510CF
3.6.1.5-46982
```

The file `fwreport.csv` is also created/overwritten with the results in CSV (comma separated values)
format. On Windows run the following command line:

```
type fwreport.csv
```

On UNIX/Linux run this command line instead:

```
cat fwreport.csv
```

The output should be similar to:

```
"10.1.1.21","3.6.1.5-46982"
"px3rack","3.6.1.5-46982"
```

## `hostlist.txt` format

The `hostlist.txt` file can have a hostname or IPv4 address on each line. Blank lines in the `hostlist.txt`
file are ignored. Lines which begin with a hash ('#') character are also ignored. This is a handy
feature to put comments in the file. It can also be used to comment out lines.

To save entering a large number of IPv4 addresses the following notation can be used:

```
10.1.1.100-150
```

The last octet can be specified as a range. In the above example the range is from 100 to 150 inclusive.

## Command line arguments

To see a list of the available command line arguments run the command:

```
python fwviasnmp.py -h
```

You should get output similar to:

```
usage: fwviasnmp.py [-h] [--hostlist HOSTLIST] [--csvfile CSVFILE]
                    [--read READ] [--oid OID] [--port PORT]
                    [--timeout TIMEOUT] [--debug]

optional arguments:
  -h, --help           show this help message and exit
  --hostlist HOSTLIST  file containing list of PDU hostnames/IP addresses
  --csvfile CSVFILE    file containing PDU names/IP addresses
  --read READ          read community string
  --oid OID            default OID for PDU firmware
  --port PORT          port number
  --timeout TIMEOUT    port number
  --debug              output additional information for debugging
```

## Command line option `--hostfile`

The `--hostfile` commmand line argument allows a different host list file to be specified instead of the
default `hostlist.txt`. For example:

```
python fwviasnmp.py --hostfile datahall.txt
```

would get the hostnames and IPv4 addresses from the `datahall.txt` file.

## Command line option `--csvfile`

By default the name of the file that the CSV data is written to is `fwreport.csv`. The `--csvfile`
command line option allows a different file be created/overwritten. For example:

```
python fwviasnmp.py --csvfile firstpass.csv
```

would write the CSV data values to the `firstpass.csv` file.

## Command line option `--read`

By default the community read string used is `public`. If your PDUs have a different community
read string (and it is strongly recommended to use a different string) then the `--read`
command line option can be used to specify it. For example:

```
python fwviasnmp.py --read mysecret
```

would use `mysecret` as the read community string.

## Command line option `--oid`

By default the `fwviasnmp.py` program sends this OID (Object IDentfier):

```
.1.3.6.1.4.1.13742.6.3.2.3.1.6.1.1.1
```

via a SNMP GET Request packet. This works on PX2 and PX3 Raritan PDUs. On older PDUs such as the PX range
(for example a PX-5805T) a different OID needs to be sent. For example you could trying sending this OID:

```
.1.3.6.1.4.1.13742.4.1.1.1.0
```

by running this command line:

```
python fwviasnmp.py --oid .1.3.6.1.4.1.13742.4.1.1.1.0
```

Note that the first '.' character can be left out so this command line:

```
python fwviasnmp.py --oid 1.3.6.1.4.1.13742.4.1.1.1.0
```

is the same.

## Command line option `--port`

The `--port` command line option allows a different UDP port number to be used for sending
and receiving the SNMP v2c packets. The default is port number `161` but to specify
a different port number use:

```
python fwviasnmp.py --port 8765
```

which would use port `8765` instead. This can be useful for testing.

## Command line option `--timeout`

When the `fwviasnmp.py` program sends a SNMP v2c get request packet it waits for
a default period of 3 seconds. The commmand line option `--timeout` can be used
to specify a different timeout value. For example to set the timeout
to 5.5 seconds use:

```
python fwviasnmp.py --timeout 5.5
```

Note that the value can be floating point.

## Command line option `--debug`

If you want to see lots of low level information while the `fwviasnmp.py` program runs
then add the `--debug` command line option. This can be useful for debugging the code and/or
seeing the low level bytes that are sent to/from the PDUs. For example:

```
python fwviasnmp.py --debug
```

might display something similar to:

```
Querying PDU 10.1.1.2 with a packet id 0xC3C42111
> 0000 : 30 31 02 01 01 04 06 70 75 62 6C 69 63 A0 24 02    01?????public?$?
> 0016 : 04 C3 C4 21 11 02 01 00 02 01 00 30 16 30 14 06    ???!???????0?0??
> 0032 : 10 2B 06 01 04 01 EB 2E 06 03 02 03 01 06 01 01    ?+?????.????????
> 0048 : 01 05 00                                           ???
< 0000 : 30 31 02 01 01 04 06 70 75 62 6C 69 63 A2 24 02    01?????public?$?
< 0016 : 04 C3 C4 21 11 02 01 00 02 01 00 30 16 30 14 06    ???!???????0?0??
< 0032 : 10 2B 06 01 04 01 EB 2E 06 03 02 03 01 06 01 01    ?+?????.????????
< 0048 : 01 80 00                                           ???
  Level: 0x00   Datatype: 0x30   Length: 0x31
  Level: 0x01   Datatype: 0x02   Length: 0x01
= 0000 : 01                                                 ?
  Level: 0x01   Datatype: 0x04   Length: 0x06
= 0000 : 70 75 62 6C 69 63                                  public
  Level: 0x01   Datatype: 0xA2   Length: 0x24
  Level: 0x02   Datatype: 0x02   Length: 0x04
= 0000 : C3 C4 21 11                                        ??!?
  Level: 0x02   Datatype: 0x02   Length: 0x01
= 0000 : 00                                                 ?
  Level: 0x02   Datatype: 0x02   Length: 0x01
= 0000 : 00                                                 ?
  Level: 0x02   Datatype: 0x30   Length: 0x16
  Level: 0x03   Datatype: 0x30   Length: 0x14
  Level: 0x04   Datatype: 0x06   Length: 0x10
= 0000 : 2B 06 01 04 01 EB 2E 06 03 02 03 01 06 01 01 01    +?????.?????????
  Level: 0x04   Datatype: 0x80   Length: 0x00
= <empty packet>
Unable to get firmware version via SNMP
```

## Limitations

There is not a way to specify a unique read only community string for each PDU. It is expected that the same read community string is
used on all PDUs listed in a host list file.

The function `packetdecode` that breaks down the SNMP response packet is quite simple and I suspect it is easy to break.
However, one `"cool"` thing about `packetdecode` is the way it uses recursion.

## Contact the author

The `fwviasnmp.py` program was written by me, Andy Cranston. If you would like to drop me a line my
email address is:

```
andy [at] cranstonhub [dot] com
```

------------------------
End of README.md (sversion 0.1.0, fversion 005, 05-january-2021)
