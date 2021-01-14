"""
python2
This script generates custom responses based on cookie labels in the domain name
"""


import base_dns_server
import sys

from dns.edns import GenericOption


class CookieServer(base_dns_server.BaseDNSServer):
    COOKIE_OPT = 10

    @property
    def num_zone_labels(self):
        """ cookie.example.com. """
        return 4

    @property
    def label_mapping(self):
        """
        for either c-cookie or s-cookie expect a hex string or the special string "none".
        "none" will result in that cookie not be included (the option is entirely excluded if none is used on c-cookie)
        Hex strings can be whatever, but valid cookies are 8 bytes for client and 8-32 bytes for server.
        If only an s-cookie is specified, will try to use c-cookie from server otherwise uses a 0'd c-cookie.
        no-edns completely strips the edns record
        bad sets the rcode to BADCOOKIE and strips the answers section if its bool is false
        """
        return {"c-cookie": [str], "s-cookie": [str], "no-edns": [], "bad": [bool]}

    def _get_cookie_from_res(self, response):
        """ :return: a string for the (combined) cookie contained in the response packet. Empty str if no cookie"""
        for o in response.options:
            if o.otype == self.COOKIE_OPT:
                return ''.join('{:02x}'.format(x) for x in o.data)
        return ""

    def _strip_cookies_from_res(self, response):
        """ removes the cookie option from the response packet if it exists """
        response.options = [o for o in response.options if o.otype != self.COOKIE_OPT]

    def modify_response(self, response, parsed_label_dict):
        # print "#" * 100
        # print "RES: %s" % str(response)
        # print "*" * 100
        # print "PARSE: %s" % parsed_label_dict

        if "no-edns" in parsed_label_dict:
            response.use_edns(False)
            return

        cookie_str = ""
        if "c-cookie" in parsed_label_dict:
            c_cookie = parsed_label_dict['c-cookie'][0] or ""
            if c_cookie == "none":
                self._strip_cookies_from_res(response)
                return
            cookie_str += c_cookie
        else:
            cookie_str += self._get_cookie_from_res(response)[:16]

        if "s-cookie" in parsed_label_dict:
            s_cookie = parsed_label_dict['s-cookie'][0] or ""
            if s_cookie != "none":
                # need client cookie first if there isn't one
                if len(cookie_str) == 0:
                    cookie_str += "0000000000000000"
                cookie_str += s_cookie

        # only set cookie if we actually have something
        if len(cookie_str) > 0:
            try:
                response.use_edns(options=[GenericOption(self.COOKIE_OPT, bytearray.fromhex(cookie_str))])
            except ValueError:
                pass

        # set BADCOOKIE rcode and clear answers
        if "bad" in parsed_label_dict:
            response.set_rcode(23)
            if not parsed_label_dict['bad'][0]:
                response.answer = []


if __name__ == "__main__":
    CookieServer.run(sys.argv)
