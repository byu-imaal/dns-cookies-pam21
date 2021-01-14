"""
Base script for measuring whether IPs return server cookies.
By default, we'll retry the server a number of times if errors are received
"""

import argparse
import json
import multiprocessing as mp
import signal
import sys
import time
from typing import Union

import dns.resolver
from dns.edns import GenericOption
from dns.message import make_query
from shared.query_parser_generator import QnameParserGenerator
from tqdm import tqdm

CLIENT_COOKIE_LENGTH = 8
COOKIE_OPT = 10
COOKIE = "1e4ddeb526a1da40"
json_keys = ["ip", "domain", "edns", "ccook", "scook", "slen", "rcode", "err", "isbind", "tsdiff"]


class QPG(QnameParserGenerator):
    """ defines query format to include timestamp and og ip """
    label_str = "$key.$ts.$ip"


def makedict(default=None):
    return {key: default for key in json_keys}


def make_cookie_query(qname: str, cookie_hex: str = COOKIE) -> dns.message:
    cookie = GenericOption(COOKIE_OPT, bytes.fromhex(cookie_hex))
    return make_query(qname, dns.rdatatype.A, use_edns=True,
                      want_dnssec=False, options=[cookie])


def extract_cooks(r: dns.message.Message) -> (str, str):
    for o in r.options:
        if o.otype == COOKIE_OPT:
            return o.data[:8].hex(), o.data[8:].hex()
    return "", ""


def is_using_bind(scook: str, current_timestamp: int = None) -> Union[None, int]:
    """
    Returns true if the server cookie is 128 bits and has a timestamp at the 5th-8th bytes.
    Bind or bind-like implementations have a timestamp at that location.
    Tolerance for the timestamp is 1hr in past and 30 min in future being valid. This seemed like a good range to use.

    :param scook: the cookie returned by the server
    :param current_timestamp: the timestamp to compare against. If none, gets current time
    :return: the difference between the bind ts and current time if bind, else None
    """
    if len(scook) != 32:  # bind cookie is 128 bits = 16 bytes = 32 hex characters
        return None
    cookie_timestamp = int(scook[8:16], 16)
    if current_timestamp is None:
        current_timestamp = int(time.time())
    if (current_timestamp - 60 * 60) <= cookie_timestamp <= (current_timestamp + 60 * 30):
        return cookie_timestamp - current_timestamp
    return None


def query(input_dict, try_again=5):
    """
    :param input_dict: should contain an ip and domain key. IP will be queried for an A record of domain
    :param try_again: if greater than 0, retry up to N times if an error or no server cookie
    :return: a response dict with all relevant data
    """
    res = makedict()
    res["ip"] = input_dict["ip"]
    if input_dict['domain'] is None:
        res['domain'] = QPG.gen('cookie-support.example.com', ip_addr=res['ip'], val=try_again)
    else:
        res["domain"] = input_dict["domain"] if "domain" in input_dict else input_dict["zone"]

    q = make_cookie_query(res["domain"])
    try:
        r: dns.message.Message = dns.query.udp(q, input_dict["ip"], timeout=5)
    except Exception as e:
        if try_again > 0:
            time.sleep(1)
            return query(input_dict, try_again - 1)
        res["err"] = str(e)
    else:
        res["ccook"], res["scook"] = extract_cooks(r)
        if res["scook"] == "" and try_again > 0:
            time.sleep(1)
            return query(input_dict, try_again - 1)
        res["tsdiff"] = is_using_bind(res["scook"])
        res["rcode"] = r.rcode()
        res["edns"] = r.edns >= 0
        res["isbind"] = res["tsdiff"] is not None
        res["slen"] = len(res["scook"]) / 2

    return res


def main(args):
    parser = argparse.ArgumentParser(description="Run a series of dns queries on a list of IPs and record cookie info")
    parser.add_argument('input', help="Input file containing a json lines with ip and optional domain keys. "
                                      "An 'A' query for 'domain' will be sent to 'ip'")
    parser.add_argument('output', help="Output file to write results to")
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    parser.add_argument('-g', '--gen-domains', help="Generate domains to query for instead of getting from jsonl",
                        action='store_true')
    args = parser.parse_args(args)

    print("Getting targets...")
    with open(args.input, 'r') as in_file:
        targets = [json.loads(t) for t in in_file.readlines()]
    if args.gen_domains:
        for t in targets:
            t["domain"] = None

    threads = min(args.num_threads, len(targets))

    print("Starting threads...")
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
