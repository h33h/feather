"""Certificate parsing helpers; no runtime, transport or process dependencies."""

import calendar
import datetime
import hashlib
import re


def reject(code):
    raise ValueError(code)


def one_pem_certificate(raw):
    values = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S)
    if len(values) != 1:
        reject("CERTIFICATE_COUNT_INVALID")
    return values[0] + b"\n"


def parse_cert_dates(raw):
    values = {}
    for line in raw.decode("ascii").splitlines():
        key, value = line.split("=", 1)
        if key in values:
            reject("CERTIFICATE_DATE_INVALID")
        values[key] = int(
            calendar.timegm(datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").timetuple())
            * 1000
        )
    if set(values) != {"notBefore", "notAfter"}:
        reject("CERTIFICATE_DATE_INVALID")
    return values["notBefore"], values["notAfter"]


def fingerprint(der, expected):
    algorithm = hashlib.sha1 if len(expected) == 40 else hashlib.sha256
    return algorithm(der).hexdigest().upper()
