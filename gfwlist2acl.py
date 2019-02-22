#!/usr/bin/env python3
"""Convert gfwlist format to ssr compatible acl file"""

import fileinput
import re
from datetime import datetime, timedelta, tzinfo
from itertools import chain


class ChinaTimezone(tzinfo):
    def tzname(self, dt):
        return 'UTC+8'

    def utcoffset(self, dt):
        return timedelta(hours=8)

    def dst(self, dt):
        return timedelta()


def convert_line(line):

    # IP
    if re.match(r'[\d\.:]+', line):
        return line

    line = re.escape(line)
    # https://adblockplus.org/en/filter-cheatsheet

    if line[0] == '/' and line[-1] == '/':
        return line[1:-1]

    # Wildcard
    line = line.replace(r'\*', '.+')
    # Seperator
    line = line.replace(r'\^', '[/:]')

    # Domain name
    if line.startswith(r'\|\|'):
        return '^https?://%s.*' % line[4:]

    # Exact address
    if line.startswith(r'\|'):
        line = '^{}'.format(line[2:])
    if line.endswith(r'\|'):
        line = '{}$'.format(line[:-2])
    # Address parts
    return line


def main():
    header = [
        '#',
        '# Home Page: {}'.format('https://github.com/NateScarlet/gfwlist.acl'),
        '# Date: {}'.format(datetime.now(ChinaTimezone()).isoformat()),
        '# URL: {}'.format(
            'https://raw.githubusercontent.com/NateScarlet/gfwlist.acl/master/gfwlist.acl'),
        '#',
    ]
    whitelist = ['', '[bypass_all]', '']
    blacklist = ['', '[proxy_list]', '']

    for line in fileinput.input():
        line = line.strip()  # type: str
        if not line or line.startswith(('!', '[AutoProxy')):
            continue

        if line.startswith('@@'):
            whitelist.append(convert_line(line[2:]))
        else:
            blacklist.append(convert_line(line))

    for i in chain(header, whitelist, blacklist):
        print(i)


if __name__ == '__main__':
    main()
