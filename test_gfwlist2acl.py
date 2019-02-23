from gfwlist2acl import convert_line


def test_convert():

    cases = [
        ('.example.com.cn', [r'\.example\.com\.cn']),
        ('', []),
        ('|https://example.com.cn/path/name', [r'^example\.com\.cn/path/name']),
        ('example.com.cn', [r'example\.com\.cn']),
        ('|example.com.cn', [r'^example\.com\.cn']),
        ('example.com.cn|', [r'example\.com\.cn$']),
        ('|example.com.cn|', [r'^example\.com\.cn$']),
        ('||example.com.cn', [r'(^|\.)example\.com\.cn']),
        ('||example.com.cn|', [r'(^|\.)example\.com\.cn$']),
        ('127.0.0.1', ['127.0.0.1']),
        ('http://127.0.0.1', ['127.0.0.1']),
        (r'/^https?:\/\/([^\/]+\.)*google\.(ac|ad|ae|af|al|am|as|at|az|ba'
         r'|be|bf|bg|bi|bj|bs|bt|by|ca|cat|cd|cf|cg|ch|ci|cl|cm|co.ao)\/.*/',
         [
             r'^([^/]+\.)*google\.(ac|ad|ae|af|al|am|as|at|az|ba)$',
             r'^([^/]+\.)*google\.(be|bf|bg|bi|bj|bs|bt|by|ca|cat)$',
             r'^([^/]+\.)*google\.(cd|cf|cg|ch|ci|cl|cm|co.ao)$',
         ])
    ]

    for case, expected in cases:
        assert convert_line(case) == expected, (case, expected)
