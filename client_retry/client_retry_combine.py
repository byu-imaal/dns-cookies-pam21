"""
This script shouldn't be needed.
Was used because `client_retry.py` had to be run twice due to a missing condition in the initial run.
This script combined the output of both runs
"""

import argparse
import json
from collections import defaultdict

from shared.fileutils import get_num_lines
from tqdm import tqdm

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('input1', help="base file")
    parser.add_argument('input2', help="file from followup test")
    parser.add_argument('output', help="Output file to write results to")
    args = parser.parse_args()

    out_dict = defaultdict(dict)
    with open(args.input1, 'r') as in_file:
        for line in tqdm(map(json.loads, in_file), total=get_num_lines(in_file)):
            out_dict[line['ip']].update(line)
    with open(args.input2, 'r') as in_file:
        for line in tqdm(map(json.loads, in_file), total=get_num_lines(in_file)):
            if "normal" in line.keys():
                line['normal2'] = line.pop('normal')
            out_dict[line['ip']].update(line)
    print(len(out_dict.values()))
    with open(args.output, 'w') as output:
        for d in out_dict.values():
            output.write(json.dumps(d) + '\n')
