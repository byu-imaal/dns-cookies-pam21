"""
This script reads from our authoritative server logs (in jsonl format) and undoes encoded data in the label
"""

import argparse
import json
import re
import sys

from shared.fileutils import get_num_lines
from shared.query_parser_generator import QnameParserGenerator
from tqdm import tqdm

seen_og_ips = set()
__QUERY_REGEX = re.compile('(^[^{]+)|([^}]+$)')


class QPG(QnameParserGenerator):
    """ defines query format to include timestamp and og ip """
    label_str = "$ip.$ts.$key"


def parse_line(line: str) -> (str, dict):
    """
    Take line as input, return og_ip and the query (as dict) if the qname could be parsed
    """
    j = json.loads(line)

    try:
        parsed = QPG.parse(j['query_message']['qname'])
        og_ip = parsed['$ip']
        qtype = parsed['$key']
    except Exception as e:
        return None, None
    else:
        res = {'og_ip': og_ip,
               'qtype': qtype,
               'query_ip': j['query_address'],
               'edns': j['query_message']['edns'] is not None,
               'qname': j['query_message']['qname'],
               'cookie': None}

    if res['edns'] and 'options' in j['query_message']['edns'].keys():
        res['cookie'] = next((o['data'] for o in j['query_message']['edns']['options'] if o['type'] == 10), None)

    return res, hash(f"{res['qname']}{j['query_port']}{j['query_message']['id']}{j['response_address']}")


def main(args):
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('input', help="log file")
    parser.add_argument('output', help="Output file to write results to")
    args = parser.parse_args(args)

    hash_set = set()

    with open(args.input, 'r') as in_file:
        with open(args.output, 'w') as output:
            for line in tqdm(map(lambda x: __QUERY_REGEX.sub('', x), in_file), total=get_num_lines(in_file)):
                res, qhash = parse_line(line)
                if res is not None and qhash not in hash_set:
                    output.write(json.dumps(res) + '\n')
                    hash_set.add(qhash)


if __name__ == "__main__":
    main(sys.argv[1:])
