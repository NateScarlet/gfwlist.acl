from gfwlist2acl import convert_line


def test_convert():

    TEST_CASES = [
        ('', ''),
        ('|https://example.com.cn/path/name', ''),
        ('example.com.cn', r'example\.com\.cn$'),
        ('|example.com.cn', r'^example\.com\.cn$'),
        ('||example.com.cn', r'(^|\.)example\.com\.cn$'),
        ('127.0.0.1', '127.0.0.1'),
        ('http://127.0.0.1', '127.0.0.1'),
    ]

    for case, expected in TEST_CASES:
        assert convert_line(case) == expected, (case, expected)
