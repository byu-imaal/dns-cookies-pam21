"""
This module contains some useful AS (autonomous system) lookup tools, most of which are
based on Team Cymru's tools. See https://www.team-cymru.com/IP-ASN-mapping.html#whois for details.
Tools include:
    
    - Get autonomous system information for a given IP address (or a list of IP addresses)
    - Can use plain sockets or dns queries
    - whois lookup in python (using sockets, a DNS query, or the actual 'whois' command)

The most useful function in here is most likely `ip_to_as_info`.
"""
import socket
from typing import Union, List


def ip_to_as_info(data: Union[str, List[str]], verbose: bool = False) -> str:
    """
    Look up AS information for the given IP address(es). Supports "bulk mode".

    Example usage:

    >>> # don't forget your imports!
    >>> from shared.asutils import ip_to_as_info
    >>>
    >>> # just lookup one IP address
    >>> ip = '1.2.3.4'
    >>> as_info = ip_to_as_info(ip)
    >>> print(as_info)
    >>> ...
    >>>
    >>> # now we're going to read a bunch of IP addresses
    >>> # from stdin and look them up at the same time
    >>> import sys
    >>> ips = [line.strip() for line in sys.stdin]
    >>> lots_of_as_info = ip_to_as_info(ips, verbose=True)
    >>> print(lots_of_as_info)
    >>> ...

    Example output for one IP address (128.187.1.1):

    6510 | 128.187.0.0/16 | US | arin | 1987-01-07

    Example output for a list of data and ``verbose=True``:

    13335   | 1.1.1.1          | 1.1.1.0/24          | AU | apnic    | 2011-08-11 | CLOUDFLARENET - Cloudflare, Inc., US
    19281   | 9.9.9.9          | 9.9.9.0/24          | US | arin     | 2017-09-13 | QUAD9-AS-1 - Quad9, US

    :param data: a single IP address or a list of IP addresses (will switch to bulk mode).
                 Note that a large list will be chunked into batches to reduce server load
    :param verbose: defaults to False. If True more data is returned. See above examples
    :return: one line per result of IP to ASN data

    Note: this function is analogous to the following:

    .. code-block:: bash

        # one IP
        nc whois.cymru.com 43 <<< '1.2.3.4'

        # lots of IPs in file
        nc whois.cymru.com 43 < ip-list-file.txt

    """

    v_flag = "verbose\n" if verbose else ""
    if isinstance(data, list):
        full_res = ""
        for i in range(0, len(data), 5000):
            request = f"begin\n" + v_flag + '\n'.join(data[i:i + 5000]) + '\nend\n'
            full_res += _ip_to_as_sender(request)
        return full_res
    else:
        return _ip_to_as_sender(f'{v_flag}{data}\n')


def _ip_to_as_sender(request: str) -> str:
    """
    helper function for ``ip_to_as_info`` this sends ``request`` to the server and returns the response

    :param request: a request string for whois
    :return: the answer formatted cleanly. 1 line per IP
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('whois.cymru.com', 43))
    sock.send(request.encode())
    raw_res = b''
    while True:
        d = sock.recv(4096)
        raw_res += d
        if not d:
            break
    sock.close()
    res = raw_res.decode()
    return '\n'.join(res.split('\n')[1:])[:-1]
