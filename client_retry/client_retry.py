"""
This script queries a given recursive server for a number of domain names we control.
Our authoritative server then responds with a custom answer per query.
We record the response the recursive resolver gives this script (a.k.a. the stub)

"""
import argparse
import json
import multiprocessing as mp
import signal
import sys

import dns.resolver
from dns.message import make_query
from shared.query_parser_generator import QnameParserGenerator
from tqdm import tqdm

# types of queries to send
qtypes = {
    "normal": "exists.cookie.example.com",
    "nocook": "exists.none.c-cookie.cookie.example.com",
    "bad-answered": "exists.t.bad.cookie.example.com",
    "bad": "exists.f.bad.cookie.example.com",
    "noedns": "exists.no-edns.cookie.example.com",
    "fake": "again.exists.0011223344556677.c-cookie.cookie.example.com"
}

json_keys = ["ip"]
json_keys.extend(list(qtypes.keys()))
sub_keys = ['qname', 'response', 'rcode', 'err']


class QPG(QnameParserGenerator):
    """ defines query format to include timestamp and og ip """
    label_str = "$ip.$ts.$key"


def query_one(input_dict, attempts: int = 3):
    res = {key: None for key in sub_keys}
    res['qname'] = QPG.gen(qtypes[input_dict['qtype']], ip_addr=input_dict['ip'], val=input_dict['qtype'])
    for i in range(attempts):
        try:
            q = make_query(res['qname'], dns.rdatatype.A)
            r: dns.message.Message = dns.query.udp(q, input_dict['ip'], timeout=5)
        except Exception as e:
            res['err'] = str(e)
            continue
        else:
            if len(r.answer) > 0:
                res['response'] = str(r.answer[0]).split()[-1]
            res['rcode'] = r.rcode()
            res['err'] = None
            break
    return {"ip": input_dict['ip'], input_dict['qtype']: res}


def main(args):
    parser = argparse.ArgumentParser(description="Run a series of dns queries for our auth server "
                                                 "on a list of recursive IPs")
    parser.add_argument('input', help="Input file containing json lines with ip and optional domain keys. "
                                      "An 'A' query for 'domain' will be sent to 'ip'")
    parser.add_argument('output', help="Output file to write results to")
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    args = parser.parse_args(args)

    print("Getting targets...")
    with open(args.input, 'r') as in_file:
        targets = [json.loads(t) for t in in_file.readlines()]

    threads = min(args.num_threads, len(targets))

    with open(args.output, 'w') as out_file:
        print(f"Spinning up {threads} threads")
        with mp.Pool(processes=threads, initializer=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)) as p:
            try:
                for qtype in qtypes.keys():
                    for t in targets:
                        t['qtype'] = qtype
                    print(f"Starting queries for {qtype}...")

                    for result in tqdm(p.imap_unordered(query_one, targets), total=len(targets), unit="query"):
                        out_file.write(json.dumps(result) + '\n')
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries.")


if __name__ == "__main__":
    main(sys.argv[1:])
