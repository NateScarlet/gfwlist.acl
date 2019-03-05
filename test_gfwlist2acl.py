"""Test `gfwlist2acl` module.  """

import sys

from gfwlist2acl import convert_line


def _generate_tests():

    cases = [
        ('.example.com.cn', [r'\.example\.com\.cn']),
        ('', []),
        ('|https://example.com.cn/path/name', []),
        ('example.com.cn', [r'example\.com\.cn']),
        ('|example.com.cn', [r'^example\.com\.cn']),
        ('example.com.cn|', [r'example\.com\.cn$']),
        ('|example.com.cn|', [r'^example\.com\.cn$']),
        ('||example.com.cn', [r'(^|\.)example\.com\.cn']),
        ('||example.com.cn|', [r'(^|\.)example\.com\.cn$']),
        ('127.0.0.1', ['127.0.0.1']),
        ('http://127.0.0.1', ['127.0.0.1']),
        ('http://127.0.0.1/', ['127.0.0.1']),
        ('https://127.0.0.1', ['127.0.0.1']),
        ('|http://127.0.0.1', ['127.0.0.1']),
        ('||http://127.0.0.1', ['127.0.0.1']),
        ('||http://127.0.0.1/', ['127.0.0.1']),
        (r'/^https?:\/\/([^\/]+\.)*google\.(ac|ad|ae|af|al|am|as|at|az|ba'
         r'|be|bf|bg|bi|bj|bs|bt|by|ca|cat|cd|cf|cg|ch|ci|cl|cm|co.ao)\/.*/',
         [
             r'^([^/]+\.)*google\.(ac|ad|ae|af|al|am|as|at|az|ba)$',
             r'^([^/]+\.)*google\.(be|bf|bg|bi|bj|bs|bt|by|ca|cat)$',
             r'^([^/]+\.)*google\.(cd|cf|cg|ch|ci|cl|cm|co.ao)$',
         ]),
        (r'/[^abc\/def].com/', [r'[^abc/def].com'])
    ]

    def create_test(case):
        def _test():
            line, expected = case
            assert convert_line(line) == expected, case
        return _test

    for index, case in enumerate(cases, 1):
        setattr(sys.modules[__name__], f'test_convert_line_{index}', create_test(case))

_generate_tests()
