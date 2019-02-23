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
    """ Convert gfwlist rule to acl format   """

    # IP
    if re.match(r'^[\d.:/]+$', line):
        return line

    # https://adblockplus.org/filters#regexps
    if line.startswith('/') and line.endswith('/'):
        return line[1:-1].replace(r'\/', '/')
    # Escape, not use `re.escape` since it behavior changes in diffrent python version
    line = re.sub(r'[.*+?^${}()|[\]\\]', lambda x: '\\{}'.format(x.group(0)), line)
    line = line.replace(r'\/', '/')

    # https://adblockplus.org/filters#basic
    line = line.replace(r'\*', '.+')
    # https://adblockplus.org/filters#separators
    line = line.replace(r'\^', r'([^a-zA-Z0-9_-.%]|$)')

    # https://adblockplus.org/filters#anchors
    if line.startswith(r'\|\|'):
        line = r'(^https?://|\.){}'.format(line[4:])
    if line.endswith(r'\|'):
        line = '{}$'.format(line[:-2])
    if line.startswith(r'\|'):
        line = '^{}'.format(line[2:])

    return line

def main():
    header = [
        '#',
        '# Date: {}'.format(datetime.now(ChinaTimezone()).isoformat()),
        '# Home Page: {}'.format('https://github.com/NateScarlet/gfwlist.acl'),
        '# URL: {}'.format(
            'https://raw.githubusercontent.com/NateScarlet/gfwlist.acl/master/gfwlist.acl'),
        '#',
        '',
        '[bypass_all]',
    ]
    blacklist = ['', '[proxy_list]', '']
    whitelist = ['', '[bypass_list]', '']

    for line in fileinput.input():
        line = line.strip()  # type: str
        # https://adblockplus.org/filters#comments
        if not line or line.startswith(('!', '[AutoProxy')):
            continue

        # https://adblockplus.org/filters#whitelist
        if line.startswith('@@'):
            whitelist.append(convert_line(line[2:]))
        else:
            blacklist.append(convert_line(line))

    for i in chain(header, blacklist, whitelist):
        print(i)


if __name__ == '__main__':
    main()
