#! /usr/bin/python3

import argparse
import requests
import time

argp = argparse.ArgumentParser(description='Check email addresses against havibeenpwned.')
argp.add_argument('-a', dest='account', help='Check a single address')
argp.add_argument('-l', dest='accountloc', help='Check against provided newline separated list')
args = argp.parse_args()

RED = '\033[91m'
BLU = '\033[94m'
GRE = '\033[92m'
END = '\033[0m'

headers = {'User-Agent': 'Python HaveIBeenPwned Checker'}
breach = 'https://haveibeenpwned.com/api/v2/breachedaccount/'
paste = 'https://haveibeenpwned.com/api/v2/pasteaccount/'
unverified = '?includeUnverified=true'
account = args.account
accountloc = args.accountloc
rlimit = 1

def breachCheck(account):
    breachr = requests.get(
        breach + account + unverified,
        headers=headers
        )

    brcode = str(breachr.status_code)

    if brcode == '200':
        bjson = breachr.json()
        print('{0}{1}'.format(BLU, account))
        return bjson
    elif brcode == '404':
        print('{0}{1}\n\t{2}No breaches found.'.format(BLU, account, RED))
        return False
    elif brcode == '400':
        print('{0}{1} {2}- Bad account'.format(BLU, account, END))
    elif brcode == '429':
        print('Hit rate limit, increasing sleep time by .3s')
        rlimit = rlimit + .3
        time.sleep(rlimit)
        breachCheck(account)
    else:
        print('Something went wrong:\n{0}'.format(breachr.content))
        quit()



def pasteCheck(account):
    paster = requests.get(
        paste + account,
        headers=headers
        )

    prcode = str(paster.status_code)

    if prcode == '200':
        pjson = paster.json()
        return pjson
    elif prcode == '404':
        print('{0}Paste Name:\n\t{1}No pastes found.\n\n'.format(BLU, RED))
        return False
    elif prcode == '400':
        print('\n\t{0}Bad account'.format(RED))
    elif prcode == '429':
        print('Hit rate limit, increasing sleep time by .3s')
        rlimit = rlimit + .3
        time.sleep(rlimit)
        pasteCheck(account)
    else:
        print('Something went wrong:\n{0}'.format(paster.content))
        quit()

def breachParse(bjson):
    print('{0}Breach Name:'.format(BLU))
    for i in range(len(bjson)):
        print('{0}\t{1}\n\t\t{2}{3}'.format(RED, bjson[i]['Name'], GRE, ', '.join(bjson[i]['DataClasses'])))

def pasteParse(pjson):
    print('{0}Paste name:'.format(BLU))
    for i in range(len(pjson)):
        print('{0}\t{1}\n\t\t{2}{3}{4}\n\n'.format(RED, pjson[i]['Title'], GRE, pjson[i]['Source'][8:-1], pjson[i]['Id']))

if account != None:
    bjson = breachCheck(account)
    if bjson:
        breachParse(bjson)
    pjson = pasteCheck(account)
    if pjson:
        pasteParse(pjson)
elif accountloc != None:
    with open(accountloc) as f:
        actlist = f.read().splitlines()
        for account in actlist:
            bjson = breachCheck(account)
            if bjson:
                breachParse(bjson)
            time.sleep(rlimit)
            pjson = pasteCheck(account)
            if pjson:
                pasteParse(pjson)
            time.sleep(rlimit)
