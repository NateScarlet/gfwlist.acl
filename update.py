#!/usr/bin/env python3

import base64
import errno
import hashlib
import os
import subprocess
from datetime import datetime
from itertools import chain
from typing import List

from gfwlist2acl import ChinaTimezone, get_acl_rules

DOWNLOAD_URL = 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt'

__dirname__ = os.path.abspath(os.path.dirname(__file__))


def _file_path(*other):
    return os.path.join(__dirname__, *other)


HASH_FILE = _file_path('hash.txt')


def download() -> List[str]:
    """Download gfwlist

    Returns:
        List[str]
    """

    return (base64.b64decode(
        subprocess.check_output(['curl', DOWNLOAD_URL], encoding='utf-8'))
        .decode('utf-8')
        .splitlines())


def main():
    blacklist, whitelist = (get_acl_rules(download()))

    h = hashlib.sha1()
    for i in chain(blacklist, ['\n\n'], whitelist):
        h.update(i.encode('utf-8'))
    result_hash = h.hexdigest()

    try:
        with open(HASH_FILE, 'r', encoding='utf-8') as f:
            if f.read() == result_hash:
                return
    except OSError as ex:
        if ex.errno != errno.ENOENT:
            raise

    common_header = ['# Home Page: https://github.com/NateScarlet/gfwlist.acl',
                     '# Date: {}'.format(datetime.now(
                         ChinaTimezone()).isoformat()),
                     '# Hash: {}'.format(result_hash)]
    with open(_file_path('gfwlist.acl'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(chain(
            ['#'],
            common_header,
            ['# URL: https://raw.githubusercontent.com/'
             'NateScarlet/gfwlist.acl/master/gfwlist.acl',
             '#',
             '',
             '[bypass_all]',
             '',
             '[proxy_list]',
             '', ],
            blacklist,
            ['', '[bypass_list]', ''],
            whitelist)))
    with open(_file_path('gfwlist.white.acl'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(chain(
            ['#'],
            common_header,
            ['# URL: https://raw.githubusercontent.com/'
             'NateScarlet/gfwlist.acl/master/gfwlist.white.acl',
             '#',
             '',
             '[proxy_all]',
             '',
             '[proxy_list]',
             '', ],
            blacklist,
            ['', '[bypass_list]', ''],
            whitelist)))
    with open(HASH_FILE, 'w', encoding='utf-8') as f:
        f.write(result_hash)

    assert subprocess.call(
        ['git', 'add', 'hash.txt', 'gfwlist.acl', 'gfwlist.white.acl']) == 0
    assert subprocess.call(
        ['git', 'commit', '-m', 'update acl files [skip ci]']) == 0
    assert subprocess.call(['git', 'tag', datetime.now(
        ChinaTimezone()).strftime('%Y.%m.%d')]) == 0
    assert subprocess.call(['git', 'push']) == 0
    assert subprocess.call(['git', 'push', '--tags']) == 0


if __name__ == '__main__':
    main()
