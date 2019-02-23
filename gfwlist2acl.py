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
    """ Convert gfwlist rule to acl format

    Reference:
        https://adblockplus.org/en/filter-cheatsheet
        https://adblockplus.org/filters#regexps
    """

    # Regexp
    if line.startswith('/') and line.endswith('/'):
        return line[1:-1]

    line = re.escape(line)

    # Regexp indicator
    line = line.replace('/', r'\/')
    # Wildcard
    line = line.replace(r'\*', '.+')
    # Seperator
    line = line.replace(r'\^', r'[\/:]')

    # Exact address end
    if line.endswith(r'\|'):
        line = '{}$'.format(line[:-2])
    # Domain name
    if line.startswith(r'\|\|'):
        line = r'^https?:\/\/{}'.format(line[4:])
    # Exact address start
    elif line.startswith(r'\|'):
        line = '^{}'.format(line[2:])

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
