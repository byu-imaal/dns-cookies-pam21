"""
Collection of functions for analyzing client retry data
Designed to run a single function via CLI
"""

import argparse
import inspect
import json
import sys
from collections import defaultdict

import numpy as np
from shared.fileutils import jl_iter


def cookie_senders(it):
    sent_cookies = set()
    for j in it:
        if j['qtype'] == 'normal' and j['cookie'] is not None and len(j['cookie']) == 16:
            sent_cookies.add(j['og_ip'])
    for ip in sent_cookies:
        print(ip)


def count_queries(it):
    counts = defaultdict(lambda: defaultdict(int))

    for j in it:
        counts[j['og_ip']][j['qtype'].lower()] += 1

    for ip, c in counts.items():
        c['ip'] = ip
        print(json.dumps(c))


def average(it):
    bad = []
    bad_answered = []
    normal = []
    for j in it:
        if "bad" in j:
            bad.append(j['bad'])
        if "bad-answered" in j:
            bad_answered.append(j['bad-answered'])
        if "normal" in j:
            normal.append(j['normal'])

    print(f'norm avg: {np.mean(normal)}')
    print(f'{np.quantile(normal, [0, .25, .5, .75, 1])}')
    print(f'bad: {np.mean(bad)}')
    print(f'{np.quantile(bad, [0, .25, .5, .75, 1])}')
    print(f'bad abs: {np.mean(bad_answered)}')
    print(f'{np.quantile(bad_answered, [0, .25, .5, .75, 1])}')


if __name__ == "__main__":
    np.set_printoptions(suppress=True, formatter={'float_kind': '{:0.2f}'.format})

    possible_funcs = []
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj) and not name.startswith('_'):
            possible_funcs.append(obj)

    parser = argparse.ArgumentParser(description="")
    parser.add_argument('input', help="Input file")
    parser.add_argument('-o', '--output', help="Optional output file", default=None, type=argparse.FileType('w'))
    parser.add_argument('func', help="Function to run", choices=[f.__name__ for f in possible_funcs])
    args = parser.parse_args()

    if args.output is not None:
        sys.stdout = args.output

    for f in possible_funcs:
        if f.__name__ == args.func:
            with open(args.input, 'r') as in_file:
                f(jl_iter(in_file))
