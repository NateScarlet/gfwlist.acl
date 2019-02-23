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


def get_domain_from_rule(line):

    # Escape, not use `re.escape` since it behavior changes in diffrent python version
    line = re.sub(r'[.*+?^${}()|[\]\\]', lambda x: '\\{}'.format(x.group(0)), line)

    # https://adblockplus.org/filters#basic
    line = line.replace(r'\*', '.+')
    # https://adblockplus.org/filters#separators
    line = line.replace(r'\^', r'([^a-zA-Z0-9_-.%]|$)')

    # https://adblockplus.org/filters#anchors
    if line.startswith(r'\|\|'):
        line = r'(^|\.){}'.format(line[4:])
    elif line.startswith(r'\|'):
        line = '^{}'.format(line[2:])
    if line.endswith(r'\|'):
        line = '{}$'.format(line[:-2])


    return get_domain_from_regexp(line)
    

def get_domain_from_regexp(line):
    if not re.match(r'^\^|\(.*(?<!\\)\^.*\)', line):
        line = '^.*{}'.format(line)
    if not line.endswith('$'):
        line = '{}.*$'.format(line)

    return line

def convert_line(line):
    """ Convert gfwlist rule to acl format   """

    if not line:
        return line

    line = line.replace(r'\/', '/')
    line = re.sub('https?://', '', line)
    # IP
    if re.match(r'^[\d.:/]+$', line):
        return ''

    # https://adblockplus.org/filters#regexps
    if line.startswith('/') and line.endswith('/'):
        return get_domain_from_regexp(line[1:-1])
    elif line.count('/'):
        return ''


    return get_domain_from_rule(line)


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
        if line.startswith(('!', '[AutoProxy')):
            continue

        # https://adblockplus.org/filters#whitelist
        is_whitelist = line.startswith('@@')
        if is_whitelist:
            line = line[2:]
        result = convert_line(line)
        if result:
            (whitelist if is_whitelist else blacklist).append(result)

    for i in chain(header, blacklist, whitelist):
        print(i)


if __name__ == '__main__':
    main()
