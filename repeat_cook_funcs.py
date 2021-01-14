"""
Collection of functions for analyzing repeat cookie data
Designed to run a single function via CLI
"""

import argparse
import inspect
import json
import math
import subprocess
import sys
from collections import Counter
from collections import defaultdict

from shared.colors import color
from tqdm import tqdm


def scook_length(it):
    lengths_cook = defaultdict(int)
    lengths_ip = defaultdict(int)
    for j in it:
        local_lengths = set()
        for q in j['queries']:
            if q['scook'] is not None and len(q['scook']) > 0:
                local_lengths.add(len(q['scook']))
                lengths_cook[len(q['scook'])] += 1
        for l in local_lengths:
            lengths_ip[l] += 1
    print(lengths_cook)
    print(lengths_ip)


def partial_interop(it):
    def is_interop(q):
        return q['scook'].startswith('01000000') and q['tsdiff'] is not None

    partial_users = defaultdict(set)

    for j in it:
        interop_count = 0
        normal_count = 0
        for q in j['queries']:
            if q['scook'] is not None and len(q['scook']) > 0:
                interop = is_interop(q)
                interop_count += 1 if interop else 0
                normal_count += 1 if not interop else 0
        if interop_count > 1 and normal_count > 1:
            partial_users[j['ip']] = set([q['scook'] for q in j['queries'] if q['scook'] is not None])

    for ip, cooks in partial_users.items():
        print(ip)
        print(f'\t{"  ".join(cooks)}')

    print(f"#### {len(partial_users.keys())} ####")


def find_statics(it):
    domains = defaultdict(list)
    for j in it:
        for q in j['queries']:
            if q['scook'] is not None and len(q['scook']) > 0:
                domains[j['ip'] + f" ({j['domain']})"].append(q['scook'])
    num_static = 0
    for d, cooks in domains.items():
        if len(set(cooks)) / len(cooks) < 0.1 and len(cooks) > 10:
            num_static += 1
            print(f'{d} : {len(set(cooks))}/{len(cooks)}')
            for c in set(cooks):
                print(f'\t{c}')
    print(f'#### {num_static} ####')


def print_non_bind_statics(it):
    domains = defaultdict(list)
    for j in it:
        for q in j['queries']:
            if q['scook'] is not None and len(q['scook']) > 0 and not q['isbind']:
                domains[j['ip'] + f" ({j['domain']})"].append(q['scook'])
    total = 0
    for d, cooks in domains.items():
        if len(cooks) > 20 and len(Counter(cooks)) == 1:
            total += 1
            print(d)
            for c, num in Counter(cooks).items():
                if num > 1:
                    print(f'\t{num}: {c}')
            print('*' * 100)
    print(f'#### {total} ####')


def print_nonces(it):
    for j in it:
        print(f"\n{'*' * 50}\n{j['domain']} - {j['ip']}")
        for q in j['queries']:
            if q['isbind']:
                print(f'{q["scook"][:8]}\t', end='')


def nonce_bit_entropy(it):
    def entropy(s):
        """ Calculate entropy. Number of bits needed to represent a byte """
        b = bytearray.fromhex(s)
        freqs = [c / len(b) for c in Counter(b).values()]
        return -sum(f * math.log2(f) for f in freqs)

    data = defaultdict(str)
    for j in it:
        for q in j['queries']:
            if q['isbind'] and not q['scook'].startswith("01000000"):
                data[j['domain']] += q['scook'][:8]

    for domain, combined_cooks in data.items():
        ent = entropy(combined_cooks)
        print(color(f'{domain} ({len(combined_cooks)}): {ent}',
                    fg=('red' if ent < 7 else 'white')))


def nonce_uniq(it):
    data = defaultdict(list)
    for j in it:
        for q in j['queries']:
            if q['isbind'] and not q['scook'].startswith("01000000"):
                data[f"{j['domain']} {j['ip']}"].append(q['scook'][:8])

    num_under_lim = 0
    for domain, cook_list in data.items():
        div = len(set(cook_list)) / len(cook_list)
        if div < .9:
            num_under_lim += 1
            # print(domain.split()[1])
            print(f'{domain} ({len(cook_list)}): {div:.4f}')
    print('*' * 50)
    print(f'Number printed: {num_under_lim} ({num_under_lim / len(data)})')


def ts_diff(it):
    data = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for j in it:
        for q in j['queries']:
            if q['tsdiff'] is not None:
                data[j['domain']][j['ip']][q['tsdiff']] += 1
    for domain, ips in data.items():
        print(domain)
        for ip, counts in ips.items():
            print(color(f'  {ip}:  ', fg=('blue' if len(counts) >= 5 else None)), end='')
            for diff, count in sorted(counts.items()):
                c_func = lambda x: 'red' if math.fabs(x) > 60 else 'green' if math.fabs(x) < 3 else None
                print(color(f'{diff}:{count}, ', fg=c_func(diff)), end='')
            print()


def ts_stats(it):
    ip_sets = defaultdict(set)
    domain_sets = defaultdict(set)

    data = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for j in it:
        for q in j['queries']:
            if q['tsdiff'] is not None:
                data[j['domain']][j['ip']][q['tsdiff']] += 1

    for domain, ips in data.items():
        domain_sets['total'].add(domain)
        for ip, counts in ips.items():
            ip_sets['total'].add(ip)
            if len(counts) >= 10:
                for d, c in sorted(counts.items()):
                    print(f'{d}:{c}  ', end='')
                print('\n' + ('#' * 50))
                ip_sets['slow'].add(ip)
                domain_sets['slow'].add(domain)
            if not any([math.fabs(t) > 60 for t in counts.keys()]):
                ip_sets['all_accurate'].add(ip)
            if all([math.fabs(t) > 60 for t in counts.keys()]):
                ip_sets['none_accurate'].add(ip)
            if any([math.fabs(t) > 60 for t in counts.keys()]) and any([math.fabs(t) <= 5 for t in counts.keys()]):
                ip_sets['some_off_in_ip'].add(ip)
                domain_sets['some_off_in_ip'].add(ip)
        if all([i in ip_sets['all_accurate'] for i in ips.keys()]):
            domain_sets['all_accurate'].add(domain)
        if not all([i in ip_sets['all_accurate'] for i in ips.keys()]) and any(
                [i in ip_sets['all_accurate'] for i in ips.keys()]):
            print(domain)
            for i in ips.keys():
                print(f'\t{i}: {i in ip_sets["all_accurate"]}')
            domain_sets['some_off_ip'].add(domain)

    ip_counts = {ip: len(s) for ip, s in ip_sets.items()}
    domain_counts = {domain: len(s) for domain, s in domain_sets.items()}

    print(f'ips: {ip_counts}')
    print(f'domains: {domain_counts}')
    print(domain_sets['some_off_ip'])


def _print_ts(ip: str, d: dict):
    # d should be a mapping of method -> list of ts diffs
    print('*' * 50)
    print(ip)
    for m, ts in d.items():
        print(f'{m:>8} {len(set(ts)):>4}|', end='')
        for i, t in enumerate(ts):
            if i == 10:
                print('|', end='')
            print(f'{t:>8}', end='')
        print()


def print_mixed_ip(it):
    """ mix of accurate and out of sync """
    data = defaultdict(lambda: defaultdict(list))

    for j in it:
        for q in j['queries']:
            if q['tsdiff'] is not None:
                data[j['ip']][q['method']].append(q['tsdiff'])

    users = 0
    for ip, d in data.items():
        # more than 8 unique diffs for none/repeat but less than 3 for follow
        # (ignore 1st since it doesn't use new cookie)
        # also ensure we had at least 5 follow cookies
        combined = set(d['follow'] + d['none'] + d['repeat'])
        if len(combined) < 10 and any([math.fabs(t) > 60 for t in combined]) and any(
                [math.fabs(t) <= 5 for t in combined]):
            users += 1
            _print_ts(ip, d)

    print(f'mixed ips: {users}')


def print_slow_ts(it):
    """  """
    diff_data = defaultdict(lambda: defaultdict(list))
    cookie_data = defaultdict(lambda: defaultdict(list))
    recv_data = defaultdict(lambda: defaultdict(list))
    for j in it:
        for q in j['queries']:
            if q['tsdiff'] is not None:
                diff_data[j['ip']][q['method']].append(q['tsdiff'])
                cookie_data[j['ip']][q['method']].append(q['tscook'])
                recv_data[j['ip']][q['method']].append(q['tsrecv'])

    users = 0
    for ip, d in diff_data.items():
        # more than 8 unique diffs for none/repeat but less than 3 for follow
        # (ignore 1st since it doesn't use new cookie)
        # also ensure we had at least 5 follow cookies
        combined = set(d['follow'] + d['none'] + d['repeat'])
        if len(combined) >= 10:
            users += 1
            print('*' * 50)
            print(ip)
            for m, ts in d.items():
                print(f'{m:>8} {len(set(ts)):>4}|', end='')
                for i, t in enumerate(ts):
                    if i == 10:
                        print('|', end='')
                    print(f'{str(cookie_data[ip][m][i])[-4:]},{t:<8}', end='')
                print()

    print(f'mixed ips: {users}')


def classify_hold_impl(it):
    """ pattern where the cookies is semi-static during none/repeat, but live in follow """
    data = defaultdict(lambda: defaultdict(list))

    for j in it:
        for q in j['queries']:
            if q['tsdiff'] is not None:
                data[j['ip']][q['method']].append(q['tsdiff'])

    users = 0
    for ip, d in data.items():
        # more than 8 unique diffs for none/repeat but less than 3 for follow
        # (ignore 1st since it doesn't use new cookie)
        # also ensure we had at least 5 follow cookies
        if (len(set(d['none'])) > 8 or len(set(d['repeat'])) > 8) and \
                len(set(d['follow'][1:])) < 3 and len(d['follow']) > 5:
            users += 1
            _print_ts(ip, d)

    print(f'users: {users}')


def classify_opposite_hold(it):
    """ pattern where the cookies is live during none then static afterwards """
    data = defaultdict(lambda: defaultdict(list))

    for j in it:
        for q in j['queries']:
            if q['tsdiff'] is not None:
                data[j['ip']][q['method']].append(q['tsdiff'])

    users = 0
    for ip, d in data.items():
        if (len(set(d['follow'])) > 8 or len(set(d['repeat'])) > 8) and \
                len(set(d['none'])) < 3 and len(d['none']) > 5:
            users += 1
            _print_ts(ip, d)

    print(f'users: {users}')


def classify_no_hold(it):
    """ """
    data = defaultdict(lambda: defaultdict(list))

    for j in it:
        for q in j['queries']:
            if q['tsdiff'] is not None:
                data[j['ip']][q['method']].append(q['tsdiff'])

    users = 0
    for ip, d in data.items():
        if len(set(d['follow'] + d['none'] + d['repeat'])) >= 10:
            if not (len(set(d['follow'][1:])) <= 4 or len(set(d['none'])) <= 4 or len(set(d['repeat'])) <= 4):
                if (d['follow'][:10] == sorted(d['follow'][:10], reverse=True) and
                    d['follow'][10:] == sorted(d['follow'][10:], reverse=True) and
                    d['repeat'][:10] == sorted(d['repeat'][:10], reverse=True) and
                    d['repeat'][10:] == sorted(d['repeat'][10:], reverse=True) and
                    d['none'][:10] == sorted(d['none'][:10], reverse=True) and
                    d['none'][10:] == sorted(d['none'][10:], reverse=True)) or \
                        (d['follow'][:10] == sorted(d['follow'][:10]) and
                         d['follow'][10:] == sorted(d['follow'][10:]) and
                         d['repeat'][:10] == sorted(d['repeat'][:10]) and
                         d['repeat'][10:] == sorted(d['repeat'][10:]) and
                         d['none'][:10] == sorted(d['none'][:10]) and
                         d['none'][10:] == sorted(d['none'][10:])):
                    users += 1
                    _print_ts(ip, d)
    print(f'users: {users}')


if __name__ == "__main__":
    possible_funcs = []
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj) and not name.startswith('_'):
            possible_funcs.append(obj)

    parser = argparse.ArgumentParser(description="")
    parser.add_argument('input', help="Input file")
    parser.add_argument('func', help="Function to run", choices=[f.__name__ for f in possible_funcs])

    args = parser.parse_args()

    lc = int(subprocess.run(args=['wc', '-l', args.input], check=True, encoding='utf-8',
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.split()[0])

    for f in possible_funcs:
        if f.__name__ == args.func:
            with open(args.input, 'r') as in_file:
                f(tqdm(map(json.loads, in_file), total=lc))
