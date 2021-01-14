#!/usr/bin/env python3
"""
This script runs a single query to get the server cookie for a given IP/domain pair.
The result is written to the specified log file
"""

import argparse
import json
import time

import dns.resolver
from dns.edns import GenericOption
from dns.message import make_query

COOKIE_OPT = 10
CLIENT_COOKIE = "1e4ddeb526a1da40"


def extract_scook(r: dns.message.Message) -> bytes:
    for o in r.options:
        if o.otype == COOKIE_OPT:
            return o.data[8:]
    return bytes()


def ind_query(domain: str, ip: str, ccookie: str) -> dict:
    d = {'ts': int(time.time()), 'ccook': ccookie, 'ip': ip, 'domain': domain,
         'err': None, 'scook': None, 'rcode': None}
    try:
        cookie_opt = GenericOption(COOKIE_OPT, bytes.fromhex(ccookie))
        q = make_query(domain, dns.rdatatype.A, use_edns=True, want_dnssec=False, options=[cookie_opt])
        r: dns.message.Message = dns.query.udp(q, ip, timeout=5)
    except Exception as e:
        d["err"] = str(e)
    else:
        d["scook"] = extract_scook(r).hex()
        d["rcode"] = r.rcode()
    return d


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('ip')
    parser.add_argument('domain')
    parser.add_argument('logfile', help="Output file to append results to")
    parser.add_argument('--ccook', type=str, default=CLIENT_COOKIE)
    args = parser.parse_args()
    with open(args.logfile, 'a') as log:
        log.write(json.dumps(ind_query(args.domain, args.ip, args.ccook)) + '\n')
