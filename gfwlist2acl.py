#!/usr/bin/env python3
"""Convert gfwlist format to ssr compatible acl file"""

import fileinput
import re
from datetime import datetime, timedelta, tzinfo
from itertools import chain

ACL_TEMPLATE = """\
#
# Home: https://github.com/NateScarlet/gfwlist.acl
# Date: {date}
# URL: https://raw.githubusercontent.com/NateScarlet/gfwlist.acl/master/{filename}
#

[{default_action}]

[proxy_list]

{blacklist}

[bypass_list]

{whitelist}
"""


class ChinaTimezone(tzinfo):
    """Timezone of china."""

    def tzname(self, dt):
        return "UTC+8"

    def utcoffset(self, dt):
        return timedelta(hours=8)

    def dst(self, dt):
        return timedelta()


def get_regexp(line):
    """Get regular expression from a line.

    Returns:
        str
    """

    # Escape, not use `re.escape` since it behavior changes in diffrent python version
    ret = re.sub(r"[.*+?^${}()|[\]\\]", lambda x: "\\{}".format(x.group(0)), line)

    # https://adblockplus.org/filters#basic
    ret = ret.replace(r"\*", ".+")
    # https://adblockplus.org/filters#separators
    ret = ret.replace(r"\^", r"([^a-zA-Z0-9_-.%]|$)")

    # https://adblockplus.org/filters#anchors
    ret = re.sub(r"^\\\|\\\|(https?\??://)?", r"(^|\.)", ret)
    ret = re.sub(r"^\\\|(https?\??://)?", "^", ret)
    ret = re.sub(r"\\\|$", "$", ret)

    return ret


def _split_long_regexp(regexp):
    match = len(regexp) > 80 and re.match(r"(.*)\((.*)\)(.*)", regexp)
    if not match:
        return [regexp]

    ret = []
    prefix = match.group(1)
    items = match.group(2).split("|")
    suffix = match.group(3)
    size = 10
    for i in range(0, len(items), size):
        chunk = items[i : i + size]
        ret.append("{}({}){}".format(prefix, "|".join(chunk), suffix))

    return ret


def get_rules(regexp):
    """Get acl rules from regular expression.

    Returns:
        List[str]
    """

    regexp = re.sub(r"\^?https?\??://", "^", regexp)
    regexp = re.sub(r"(\.\*)+$", "", regexp)
    regexp = re.sub(r"/$", "$", regexp)

    # Exclude pathname rule, since ssr only accept domain match
    if "/" in re.sub(
        r"(\[\^.*)/(.*\])", lambda match: match.group(1) + match.group(2), regexp
    ):
        return []

    ret = _split_long_regexp(regexp)

    # SSR can not deal with too long rule in one line
    ret = [i for i in ret if len(i) < 500]
    return ret


def convert_line(line):
    """Convert a input line to acl rules

    Returns:
        List[str]
    """

    if not line:
        return []

    line = line.replace(r"\/", "/")

    # IP
    match = re.match(
        r"^\|*(?:https?://)?(\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}(?::\d{1,5})?)/*$", line
    )
    if match:
        return [match.group(1)]

    # https://adblockplus.org/filters#regexps
    if line.startswith("/") and line.endswith("/"):
        return get_rules(line[1:-1])

    return get_rules(get_regexp(line))


def get_acl_rules(_content):
    """Get acl rules from gfwlist

    Args:
        _content (Iterable[str]): gfwlist data

    Returns:
        (List[str], List[str]): (blacklist, whitelist)
    """
    content = _content
    content = (i.strip() for i in content)
    # https://adblockplus.org/filters#comments
    content = [i for i in content if not i.startswith(("!", "[AutoProxy"))]

    # https://adblockplus.org/filters#whitelist
    blacklist = chain(*(convert_line(i) for i in content if not i.startswith("@@")))
    whitelist = chain(*(convert_line(i[2:]) for i in content if i.startswith("@@")))

    return list(blacklist), list(whitelist)


def main():
    blacklist, whitelist = get_acl_rules(fileinput.input())

    print(
        ACL_TEMPLATE.format(
            date=datetime.now(ChinaTimezone()).isoformat(),
            filename="gfwlist.acl",
            default_action="bypass_all",
            blacklist="\n".join(blacklist),
            whitelist="\n".join(whitelist),
        )
    )


if __name__ == "__main__":
    main()
