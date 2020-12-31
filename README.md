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
                    [--read READ] [--port PORT] [--timeout TIMEOUT]

optional arguments:
  -h, --help           show this help message and exit
  --hostlist HOSTLIST  file containing list of PDU hostnames/IP addresses
  --csvfile CSVFILE    file containing PDU names/IP addresses
  --read READ          read community string
  --port PORT          port number
  --timeout TIMEOUT    port number
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
End of README.md
