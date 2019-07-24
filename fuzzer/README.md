# fuzzer.py

fuzzer.py is a `python3` command-line program fuzzes an [an example web 
app](https://www.cs.tufts.edu/comp/20/hackme.php). The main goal of `fuzzer` 
is to test if the web app is vulnerable to XSS attacks.

fuzzer works by first loading a [giant seclist of fuzzing 
payloads](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing) 
into an array of payloads. For each payload, `fuzzer` sends an HTTP POST 
request to the web app and stores the responses. To calculate the success 
rate of the XSS attacks, `fuzzer` calculates the expected percent difference 
between HTTP response bodies from ineffective payloads (assuming that the 
number of ineffective payloads is greater than the number of effective 
payloads). `fuzzer` then counts the number of payloads resulting in a 
percent difference greater than the expected percent difference, thus 
effectively making an estimation for the number of potentially successful 
reflected XSS attacks.

### Imported Modules
- `SequenceMatcher`
- `requests`
- `random`
- `math`
- `glob`
- `sys`
- `os`

### Usage
```
foo@bar:~$ python3 fuzzer.py <SECLIST_DIRECTORY>
                <SECLIST_DIRECTORY>: path to the directory
```

### Requirements
- `python3`
- `requests`

### Implementation Details
- All requirements have been correctly implemented
- Did not receive help from anyone
- Lab took about 5 hours to do
- Would like to optimize the application for better run-times
- Would also like to use a better string-distance algorithm

