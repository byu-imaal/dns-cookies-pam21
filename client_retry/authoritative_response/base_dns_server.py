#!/usr/bin/env python
"""
python2
This script serves as a base for custom authoritative server responses (`cookie_dns_server` extends this class)

The idea is to dispatch DNS queries (based on a key label) to these servers. They then modify the response generated by
a standard auth. server implementation based on other labels in the query.
"""

import Queue
import socket
import sys
import threading
import time
import traceback
from abc import ABCMeta, abstractmethod, abstractproperty

import dns.exception
import dns.message


class BaseDNSServer:
    """
    An abstract DNSServer class.
    To create a server that handles custom labels values, extend this class then implement the abstract methods below.
    The basic idea is to define a dictionary of key labels to sub labels then use this dictionary to modify the response
    Start the server by calling `Server.run(sys.argv)`
    """
    __metaclass__ = ABCMeta

    def __init__(self, inaddr, inport, outaddr, outport, backend_domain):
        self._backend_domain = backend_domain

        af = socket.AF_INET6 if ":" in inaddr else socket.AF_INET
        self._insock = socket.socket(af, socket.SOCK_DGRAM)
        self._inaddr = inaddr
        self._inport = inport

        af = socket.AF_INET6 if ":" in outaddr else socket.AF_INET
        self._outsock = socket.socket(af, socket.SOCK_DGRAM)
        self._outaddr = outaddr
        self._outport = outport

        self._request_queue = Queue.Queue()

    @abstractproperty
    def num_zone_labels(self):
        """
        :return: int The number of labels for the base zone. e.g. `*.example.com` has 3 base labels (includes root).
                 Essentially this number of labels will be stripped and replaced with `backend_domain` before sending
                 to the backend
        """
        raise NotImplementedError

    @abstractproperty
    def label_mapping(self):
        """
        :return: a dict mapping key labels to their expected sub-label types.
        Flags can be created with an empty array (see "bool" below)

        Example:
            label_mapping (set here): {"one-str": [str], "two-nums" [int, int], "bool"}

            qname: 3.4.two-nums.hello.one-str.bool.example.com
            will provide to `modify_response`: {"one-str": ["hello"], "two-nums": [4, 3], "bool": []}

            qname: there.one-str.example.com
            will provide to `modify_response`: {"one-str": ["there"]}

        Note:
            If using a bool type in the values for a key, the label should start with "f" or "t"
            This will be converted to a bool when passed to `modify_response()`
        """
        raise NotImplementedError

    @abstractmethod
    def modify_response(self, response, parsed_label_dict):
        """
        The main method for subclasses to implement.
        Provides a response and a dict of parsed labels based on `label_mapping`
        :param response: a response to the original query as provided by the backend server
        :param parsed_label_dict: the parsed dict that follows the format of ``label_mapping``
               but with values. Any value may be None if it couldn't be parsed. Unexpected values
               must also be handled in case of badly formed queries
        :return: N/A. Method should modify response object directly
        """
        raise NotImplementedError

    def _remove_special_labels_request(self, request, num_special_labels):
        """
        Strips special labels used by this class in a request. Called before sending to backend.
        Specifically it will strip all zone labels and special labels then add back the labels in `backend_domain`
        :param request: the request
        :param num_special_labels: the number of special labels that were consumed by this class
        """
        q_rrset = request.question[0]
        qname = q_rrset.name
        q_rrset.name = dns.name.Name(qname[:-(num_special_labels + self.num_zone_labels)] + self._backend_domain.labels)

    def _add_special_labels_response(self, response, orig_qname):
        """
        modifies a response to replaces all instances of the qname with `orig_qname`.
        In practice this undoes `_remove_special_labels_request()` so that we can send the correct qname to the
        incoming server
        :param response: a response packet
        :param orig_qname: the original qname received from the incoming server
        :return:
        """
        q_rrset = response.question[0]
        qname = q_rrset.name
        for sec in response.question, response.answer, \
                response.authority, response.additional:
            for rrset in sec:
                if rrset.name == qname:
                    rrset.name = orig_qname
        for rrset in response.authority:
            if rrset.name == self._backend_domain and \
                    rrset.rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS):
                rrset.name = dns.name.Name(orig_qname[-self.num_zone_labels:])

    def _handle_request(self, buf, addr):
        """
        Handles a single request (buf) from an addr.
        In summary, the following steps are performed.
          1. receives request from incoming server (addr)
          2. strips special labels from qname
          3. sends query to outgoing server
          4. gets response from outgoing server
          5. modifies response as desired (see `modify_response()`)
          6. sends response to incoming server (addr)

        :param buf: the request
        :param addr: the server that sent the request
        """
        try:
            request = dns.message.from_wire(buf)
        except dns.exception.DNSException as e:
            # there was a problem passing the message; just proxy it without
            # any manipulation
            sys.stderr.write(str(e) + '\n')

            self._outsock.send(buf)
            buf = self._outsock.recv(4096)
            self._insock.sendto(buf, addr)
            return

        orig_qname = request.question[0].name
        parsed_labels, num_special_labels = self._qname_to_dict(orig_qname)
        self._remove_special_labels_request(request, num_special_labels)

        # send/receive
        self._outsock.send(request.to_wire())
        buf = self._outsock.recv(4096)
        response = dns.message.from_wire(buf)

        self._add_special_labels_response(response, orig_qname)
        self.modify_response(response, parsed_labels)

        try:
            self._insock.sendto(response.to_wire(), addr)
        except dns.exception.TooBig:
            response.answer = []
            response.authority = []
            response.additional = []
            self._insock.sendto(response.to_wire(), addr)

    @staticmethod
    def _cast_label(out_type, label):
        """
        Cast a label string to out_type. Special handling for bools
        :param out_type: the type to cast to
        :param label: the label being cast
        :return: the label converted to out_type or None if an error occured
        """
        try:
            if out_type == bool:
                return not label.lower().startswith("f") and label != "0"
            return out_type(label)
        except (TypeError, ValueError) as e:
            sys.stderr.write("Error converting label value in map\n")
            sys.stderr.write(str(e) + '\n')
            return None

    def _qname_to_dict(self, qname):
        """
        maps a qname to a dict of label -> [vals] based on the the `label_mapping`.
        Prints errors if type conversion fails or unexpected labels are found

        Example:
        qname: 7.3.a.example.com
        mapping: {"a": [int, int]}
        zone_length: 2
        output: {"a": [3, 7]}

        :param qname: the DNS qname
        :return: a dict of same structure as mapping, but with parsed values.
        Also an int for the number of labels consumed to create the dict
        """
        ret = {}
        labels = qname.labels[::-1]
        i = self.num_zone_labels
        while i < len(labels):
            # only continue if this is a key label
            if labels[i] not in self.label_mapping.keys():
                break
            key = labels[i]
            ret[key] = []
            # for each expected subpart, pull from qname and convert to proper type
            for subpart_type in self.label_mapping[labels[i]]:
                i += 1
                # handle possible qname minimization, if the query is short, just set values as None
                if i >= len(labels):
                    ret[key].append(None)
                else:
                    ret[key].append(self._cast_label(subpart_type, labels[i]))
            i += 1
        return ret, i - self.num_zone_labels

    def _handle_requests(self):
        """
        Thread function. Endless loop that takes queries from queue and processes them
        """
        while True:
            try:
                buf, addr = self._request_queue.get()
                self._handle_request(buf, addr)
            except:
                traceback.print_exc()
                time.sleep(3)

    def _start(self):
        """
        Begins server. Connects/binds sockets, starts consumer threads, then continuously adds incoming packets to queue
        """
        self._insock.bind((self._inaddr, self._inport))
        self._outsock.connect((self._outaddr, self._outport))

        num_threads = 40
        for i in range(num_threads):
            t = threading.Thread(target=self._handle_requests)
            t.daemon = True
            t.start()

        while True:
            try:
                buf, addr = self._insock.recvfrom(2048)
                self._request_queue.put((buf, addr))
            except Exception as e:
                traceback.print_exc()

    @classmethod
    def run(cls, args):
        """
        External function for running server.
        :param args: CLI args
        :return: the running server instance
        """
        if len(args) != 4:
            sys.stderr.write('Usage: %s <inaddr>:<inport> <outaddr:outport> <backend_domain>\n' % (args[0]))
            sys.stderr.write('\tin* - where to listen for incoming packets\n')
            sys.stderr.write('\tout* - where to forward requests to for concrete answers\n')
            sys.stderr.write('\tbackend_domain - the base qname that the out server is auth for\n')
            sys.exit(1)

        inaddr, inport = args[1].rsplit(':', 1)
        outaddr, outport = args[2].rsplit(':', 1)
        inport = int(inport)
        outport = int(outport)
        backend_domain = dns.name.from_text(args[3])

        d = cls(inaddr, inport, outaddr, outport, backend_domain)
        d._start()
        return d

