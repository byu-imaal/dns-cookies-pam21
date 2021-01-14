import os
import string
import subprocess
from typing import Union, TextIO
from tqdm import tqdm
import json


def get_num_lines(file: Union[str, TextIO]) -> int:
    """
    Gets the number of lines in a file. Uses ``wc -l`` which seems to be the fastest method for larger files.
    Specifically counts the number of newline characters (thus no trailing newline may reduce count by 1)

    :param file: the file to get line counts for. Either a string or an open text file (returned by ``open()``)
    :raises CalledProcessError: if there was an error with the subprocess
    :return: the number of lines in the file as an int
    """
    out = subprocess.run(args=['wc', '-l', file if isinstance(file, str) else file.name], check=True,
                         encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return int(out.stdout.split()[0])


def get_free_filename(filename: str, format_str: str = "{file}_{uniq}.{ext}"):
    """
    Get a filename that's free so we don't overwrite anything. Appends a consecutive digit to the end of the name
    until it is unique. Note that this method respects file extensions.

    Example: if there is already ``example.txt`` in a directory,

    calling ``get_free_filename("example".txt, format_str="{uniq:02d}__{file}")`` will return: ``01__example.txt``

    calling ``get_free_filename("example".txt, format_str="{file}.{uniq}.{ext}")`` will return: ``example.1.txt``

    :param filename: the desired filename
    :param format_str: The string to format the filename with. Can include ``{file}`` for the filename, ``{uniq}``
                        for the unique id and optionally ``{ext}`` to include the file extension separately
    :return: the orginal filename if it doesn't exist, otherwise a filename following the ``format_str`` pattern
    """

    fmt_keys = [t[1] for t in string.Formatter().parse(format_str) if t[1] is not None]
    if any(key not in ["file", "uniq", "ext"] for key in fmt_keys):
        raise KeyError("Invalid key for file format. Allowed keys are {file, uniq, ext}")

    n = 1
    if "." in filename and "ext" in format_str:
        parts = filename.split('.')
        original, ext = '.'.join(parts[:-1]), parts[-1]
    else:
        original, ext = filename, ""

    while os.path.isfile(filename):
        filename = format_str.format(file=original, uniq=n, ext=ext)
        n += 1

    return filename


def jl_iter(file: TextIO, with_tqdm=True) -> iter:
    """
    Create a json lines iterator from an open file.

    Example usage:
    with open('file.jsonl', 'r') as in_file:
        for line in jl_iter(in_file):
            print(line.keys())

    :param file: the open file to be used
    :param with_tqdm: if set, wraps iterator in tqdm progress bar
    :return: an iterator of dictionaries
    """
    if with_tqdm:
        return tqdm(map(json.loads, file), total=get_num_lines(file))
    else:
        return map(json.loads, file)
