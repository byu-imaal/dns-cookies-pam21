"""
This script sends a number of queries to record the server cookies returned by a given domain.
There are 3 methods of repetition:
 1. none: In each query, do not include a server cookie
 2. repeat: In each query, include the first server cookie received from the IP
 3. follow: In each query, use the most recent server cookie received from the IP
"""

import argparse
import json
import multiprocessing as mp
import signal
import sys
import time
from functools import partial
from typing import Union, Tuple

import dns.resolver
from dns.edns import GenericOption
from dns.message import make_query
from tqdm import tqdm

COOKIE_OPT = 10
CLIENT_COOKIE = "1e4ddeb526a1da40"
json_keys = ["ip", "domain", "num_sent", "queries"]
query_keys = ["sent", "edns", "scook", "rcode", "isbind", "tsdiff", "tsrecv", "tscook", "err", "method"]


def makedict(default=None, keys=json_keys):
    return {key: default for key in keys}


def extract_scook(r: dns.message.Message) -> bytes:
    for o in r.options:
        if o.otype == COOKIE_OPT:
            return o.data[8:]
    return bytes()


def is_using_bind(scook: str, current_timestamp: int = None) -> Tuple[Union[None, int], int]:
    """
    Returns true if the server cookie is 128 bits and has a timestamp at the 5th-8th bytes.
    Bind or bind-like implementations have a timestamp at that location.
    Tolerance for the timestamp is 1hr in past and 30 min in future being valid. This seemed like a good range to use.

    :param scook: the cookie returned by the server
    :param current_timestamp: the timestamp to compare against. If none, gets current time
    :return: the cookie timestamp or None if not bind-like. Also the current timestamp
    """
    if current_timestamp is None:
        current_timestamp = int(time.time())

    if len(scook) != 32:  # bind cookie is 128 bits = 16 bytes = 32 hex characters
        return None, current_timestamp
    cookie_timestamp = int(scook[8:16], 16)

    if (current_timestamp - 60 * 60) <= cookie_timestamp <= (current_timestamp + 60 * 30):
        return cookie_timestamp, current_timestamp
    return None, current_timestamp


def ind_query(domain: str, ip: str, method: str, scookie: str) -> dict:
    # NOTE: didn't handle a None scookie
    d = makedict(keys=query_keys)
    try:
        cookie_opt = GenericOption(COOKIE_OPT, bytes.fromhex(CLIENT_COOKIE + scookie))
        q = make_query(domain, dns.rdatatype.A, use_edns=True, want_dnssec=False, options=[cookie_opt])
        d["sent"] = scookie
        r: dns.message.Message = dns.query.udp(q, ip, timeout=5)
    except Exception as e:
        d["err"] = str(e)
    else:
        d["scook"] = extract_scook(r).hex()
        d["tscook"], d["tsrecv"] = is_using_bind(d["scook"])
        if d["tscook"] is not None:
            d["tsdiff"] = d["tscook"] - d["tsrecv"]
        d["isbind"] = d["tscook"] is not None
        d["rcode"] = r.rcode()
        d["edns"] = r.edns >= 0
        d["method"] = method
    return d


def query(params):
    if params['method'] == "all":
        params["method"] = "none"
        none_res = query(params)
        params["method"] = "repeat"
        repeat_res = query(params)
        params["method"] = "follow"
        follow_res = query(params)
        none_res["num_sent"] += repeat_res["num_sent"] + follow_res["num_sent"]
        none_res["queries"].extend(repeat_res['queries'])
        none_res["queries"].extend(follow_res['queries'])
        return none_res

    res = makedict()
    res["ip"] = params["ip"]
    res["domain"] = params["domain"]
    res["num_sent"] = params["number"]
    res["queries"] = []

    qry = partial(ind_query, params["domain"], params["ip"], params["method"])

    prev_query = qry("")

    for i in range(params["number"]):
        time.sleep(params["delay"] if i % 10 != 0 else params["delay"] * params["delay-mult"])
        if params["method"] == "none":
            res["queries"].append(qry(""))
        elif params["method"] == "repeat":
            res["queries"].append(qry(prev_query["scook"]))
        else:
            q = qry(prev_query["scook"])
            res["queries"].append(q)
            if q["scook"] is not None:
                prev_query = q

    return res


def main(args):
    parser = argparse.ArgumentParser(description="Running a series of dns queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a json lines with ip and domain keys")
    parser.add_argument('output', help="Output file to write results to")
    parser.add_argument('mode', help="How to send server cookie.\n"
                                     "none = never send server cookie\n"
                                     "repeat = always send first server cookie received\n"
                                     "follow = send last server cookie received\n"
                                     "all = do all three above and combine into single result",
                        choices=["none", "repeat", "follow", "all"])
    parser.add_argument('-t', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    parser.add_argument('-n', '--num-queries', help="Number of queries to run on a single IP", default=20, type=int)
    parser.add_argument('-d', '--delay', help="Delay in seconds between queries to a single IP", default=1, type=float)
    parser.add_argument('--delay-mult', help="Every 10 queries increase delay by this factor", default=60, type=int)

    args = parser.parse_args(args)

    with open(args.input, 'r') as in_file:
        targets = [json.loads(t) for t in in_file.readlines()]

    for t in targets:
        t["number"] = args.num_queries
        t["method"] = args.mode
        t["delay"] = args.delay
        t["delay-mult"] = args.delay_mult
        if "domain" not in t.keys():
            t["domain"] = "cookie-repeat.example.com"

    threads = min(args.num_threads, len(targets))

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
