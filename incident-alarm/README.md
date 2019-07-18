# alarm.py

alarm.py is a `python3` command-line program that alerts the user if 
it detects plaintext username:password pairs transfered through HTTP
basic auth or through FTP while listening on an interface or while 
reading a pcap file. The proram also alerts the user if it detects 
FIN, XMAS, and NULL scans.

alarm.py works by 

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

### Implementation Details
- All requirements have been correctly implemented
- Did not receive help from anyone
- Lab took about 7 hours to do
- Would like to change string formatting from using "%" syntax to
  using ".format" due to future deprecation reasons

### Questions
1. Are the heuristics used in this assignment to determine 
   incidents "even that good"?

        Not really. The heuristics only cover the basic incidents and 
        doesn't handle more complex techniques that attackers may use 
        to cover their tracks. Furthermore, the approach does not take 
        into factor honeypots nor does it contain a way of credibly 
        determining attribution.

2. If you have spare time in the future, what would you add to the 
   program or do differently with regards to detecting incidents?

        In regards to plaintext data capturing, I would like to expand 
        the program to include the other insecure protocols. I would also 
        develop a method for determining successful authentication with 
        captured username:password pairs. I would also like to detect 
        source IP patterns to catch DDoS attacks, decoy scans, and other 
        useful info. Additionally, I would like to refactor to program 
        to split it into modules.
