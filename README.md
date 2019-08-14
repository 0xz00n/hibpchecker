# hibpchecker
Checks email addresses, singularly or within lists, against haveibeenpwned

# API Key
API key must be placed into a file named `hibpapikey.py` with the following format:
```
apikey = "apikeygoeshere"
```

### Help Output
```
$ ./hibpcheck.py --help
usage: hibpcheck.py [-h] [-a ACCOUNT] [-l ACCOUNTLOC]

Check email addresses against havibeenpwned.

optional arguments:
  -h, --help     show this help message and exit
  -a ACCOUNT     Check a single address
  -l ACCOUNTLOC  Check against provided newline separated list
  ```
