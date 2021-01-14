"""Default QnameComponent extensions that are included in the base QueryParserGenerator class"""

import base64
import binascii
import random
import socket
import string
import struct
import time

from shared.qpg_component_base import QnameComponent


class QnameKeyword(QnameComponent):
    id = "$key"
    exceptions = []

    @classmethod
    def generate(cls, val) -> str:
        return str(val)


class QnameIP(QnameComponent):
    id = "$ip"
    exceptions = [socket.error, binascii.Error, OSError]

    @classmethod
    def generate(cls, ip_addr):
        if ':' in ip_addr:
            return base64.b32encode(socket.inet_pton(socket.AF_INET6, ip_addr))[:-6].lower().decode()
        else:
            return base64.b32encode(socket.inet_pton(socket.AF_INET, ip_addr))[:-1].lower().decode()

    @classmethod
    def parse(cls, label):
        if len(label) > 7:
            return socket.inet_ntop(socket.AF_INET6, base64.b32decode('{}======'.format(label).upper()))
        else:
            return socket.inet_ntop(socket.AF_INET, base64.b32decode('{}='.format(label).upper()))


class QnameTimestamp(QnameComponent):
    id = "$ts"
    exceptions = [binascii.Error, struct.error]

    @classmethod
    def generate(cls, timestamp: float = None) -> str:
        if timestamp is None:
            timestamp = time.time()
        return base64.b32encode(struct.pack(">I", int(timestamp)))[:-1].lower().decode()

    @classmethod
    def parse(cls, label: str) -> int:
        return struct.unpack('>I', base64.b32decode(label + '=', casefold=True))[0]


class QnameMicroSeconds(QnameComponent):
    id = "$tsu"
    exceptions = []

    @classmethod
    def generate(cls, timestamp: float = None) -> str:
        if timestamp is None:
            timestamp = time.time()
        return str(int(10000000 * (timestamp - int(timestamp))))

    @classmethod
    def parse(cls, label: str) -> int:
        return int(label)


class QnameHostname(QnameComponent):
    id = "$host"
    exceptions = [socket.error]

    @classmethod
    def generate(cls) -> str:
        return socket.gethostname()


class QnameUnique(QnameComponent):
    """
    This class is NOT thread-safe.
    If multithreading is needed, pre-generate the qnames serially
    """
    id = "$uniq"
    exceptions = []
    __num = 0

    @classmethod
    def generate(cls) -> str:
        cls.__num += 1
        return str(cls.__num)


class QnameRandomAlpha(QnameComponent):
    id = "$randalpha"
    exceptions = []

    @classmethod
    def generate(cls, length: int = 8) -> str:
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


class QnameRandomNumeric(QnameComponent):
    id = "$randnum"
    exceptions = []

    @classmethod
    def generate(cls, length: int = 8) -> str:
        return ''.join(random.choice(string.digits) for _ in range(length))


class QnameRandomAlphaNumeric(QnameComponent):
    id = "$randalphanum"
    exceptions = []
    ascii_lower_digits = string.ascii_lowercase + string.digits

    @classmethod
    def generate(cls, length: int = 8) -> str:
        return ''.join(random.choice(cls.ascii_lower_digits) for _ in range(length))


class QnameRandomBase32(QnameComponent):
    id = "$randb32"
    exceptions = []

    @classmethod
    def generate(cls, timestamp: float = None) -> str:
        if timestamp is None:
            timestamp = time.time()
        timestamp = int(timestamp * 100000)
        b32 = base64.b32encode(struct.pack('>Q', timestamp)).decode().lower()
        slc = slice(0, b32.index('='))
        b32 = b32[slc]
        return ''.join(random.sample(b32, len(b32)))
