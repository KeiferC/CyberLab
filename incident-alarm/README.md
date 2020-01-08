# alarm.py

alarm.py is a `python3` command-line program that alerts the user if 
it detects plaintext username:password pairs transfered through HTTP
basic auth or through FTP while listening on an interface or while 
reading a pcap file. The proram also alerts the user if it detects 
FIN, XMAS, and NULL scans.

### Imported Modules
- `scapy`
- `pcapy`
- `argparse`
- `base64`
- `sys`
- `re`

### Usage
```
foo@bar:~$ python3 alarm.py [-h] [-i] <INTERFACE> [-r] <PCAP_FILE>
```

### Requirements
- `python3`
- `scapy`
- `pcapy`
