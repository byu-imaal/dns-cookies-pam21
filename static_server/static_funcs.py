"""
Collection of functions for analyzing static cookie data
Designed to run a single function via CLI
"""

import argparse
import datetime
import inspect
import sys
from collections import defaultdict

from shared.fileutils import jl_iter


def ips_match(it):
    res = defaultdict(set)

    for j in it:
        res[j['ip']].add(j['scook'])

    cooks = [tuple(l) for l in res.values()]

    print(len(set(list(cooks))) == 1)


def print_rollover(it):
    res = defaultdict(list)

    for j in it:
        if len(res[j['ip']]) == 0 or res[j['ip']][-1][1] != j['scook']:
            res[j['ip']].append((j['ts'], j['scook']))

    for ip, data in res.items():
        print(ip)
        for d in data:
            print(f'\t{datetime.datetime.fromtimestamp(d[0])} - {d[1]}')


if __name__ == "__main__":
    possible_funcs = []
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj) and not name.startswith('_'):
            possible_funcs.append(obj)

    parser = argparse.ArgumentParser(description="")
    parser.add_argument('input', help="Input file")
    parser.add_argument('func', help="Function to run", choices=[f.__name__ for f in possible_funcs])

    args = parser.parse_args()

    for f in possible_funcs:
        if f.__name__ == args.func:
            with open(args.input, 'r') as in_file:
                f(jl_iter(in_file))
