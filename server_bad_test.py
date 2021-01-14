"""
Script for testing how servers respond the various 'bad' cookies.
"""

import argparse
import json
import multiprocessing as mp
import signal
import sys
import time
from functools import partial

import dns.resolver
from dns.edns import GenericOption
from dns.message import make_query
from tqdm import tqdm

COOKIE_OPT = 10
CLIENT_COOKIE = "1e4ddeb526a1da40"
FAKE_SERVER_COOKIE = "00112233445566778899aabbccddeeff"

query_keys = ["sent", "edns", "scook", "response", "rcode", "err"]
methods = ['normal', 'none', 'fake']
json_keys = ["ip", "domain", "num_sent"]
json_keys.extend(methods)


def makedict(default=None, keys=json_keys):
    return {key: default for key in keys}


def extract_scook(r: dns.message.Message) -> bytes:
    for o in r.options:
        if o.otype == COOKIE_OPT:
            return o.data[8:]
    return bytes()


def ind_query(domain: str, ip: str, scookie: str, attempts: int = 3) -> dict:
    d = makedict(keys=query_keys)
    for i in range(attempts):
        try:
            cookie_opt = GenericOption(COOKIE_OPT, bytes.fromhex(CLIENT_COOKIE + scookie))
            q = make_query(domain, dns.rdatatype.A, use_edns=True, want_dnssec=False, options=[cookie_opt])
            d["sent"] = scookie
            r: dns.message.Message = dns.query.udp(q, ip, timeout=5)
        except Exception as e:
            d['err'] = str(e)
            continue
        else:
            if len(r.answer) > 0:
                d['response'] = str(r.answer[0]).split()[-1]
            d["scook"] = extract_scook(r).hex()
            d["rcode"] = r.rcode()
            d["edns"] = r.edns >= 0
            break
    return d


def query(params):
    res = makedict()
    res["ip"] = params["ip"]
    res["domain"] = params["domain"]
    res["num_sent"] = params["number"]

    for m in methods:
        qry = partial(ind_query, params["domain"], params["ip"])
        prev_query = qry("")
        res[m] = []
        for _ in range(params["number"]):
            time.sleep(1)
            if m == "none":
                res[m].append(qry(""))
            elif m == "fake":
                res[m].append(qry(FAKE_SERVER_COOKIE))
            else:
                q = qry(prev_query["scook"])
                res[m].append(q)
                if q["scook"] is not None:
                    prev_query = q

    return res


def main(args):
    parser = argparse.ArgumentParser(description="Running a series of dns queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a json lines with ip and domain keys")
    parser.add_argument('output', help="Output file to write results to")
    parser.add_argument('-t', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    parser.add_argument('-n', '--num-queries', help="Number of queries to run on a single IP", default=5, type=int)

    args = parser.parse_args(args)

    with open(args.input, 'r') as in_file:
        targets = [json.loads(t) for t in in_file.readlines()]

    for t in targets:
        t["number"] = args.num_queries
        if "domain" not in t.keys():
            t["domain"] = "cookie-test.example.com"

    threads = min(args.num_threads, len(targets))

    print("Beginning threads...")
    with open(args.output, 'w') as output:
        with mp.Pool(processes=threads, initializer=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)) as p:
            try:
                for result in tqdm(p.imap_unordered(query, targets), total=len(targets), unit="query"):
                    output.write(json.dumps(result) + "\n")
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries.")


if __name__ == "__main__":
    main(sys.argv[1:])
