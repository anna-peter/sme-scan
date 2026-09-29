"""
Thin wrappers around dnspython.

Every network call in the project goes through this module. The checks
themselves only see plain Python values (lists of strings), which keeps them
easy to read and easy to test without a network.
"""

from __future__ import annotations

import dns.exception
import dns.resolver
import dns.reversename

# Public resolvers, so results don't depend on your ISP's cache
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


class LookupFailed(Exception):
    """The query itself failed (timeout, SERVFAIL, ...), so the answer is unknown.

    This is deliberately different from "the record does not exist", which is
    a real answer and is returned as an empty list.
    """


def make_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    # configure=False: don't read /etc/resolv.conf, use only the servers below
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = PUBLIC_RESOLVERS
    r.timeout = timeout      # per server attempt
    r.lifetime = timeout * 2  # whole query, including retrying the 2nd server
    return r


def _resolve(resolver, name: str, rdtype: str) -> list:
    try:
        return list(resolver.resolve(name, rdtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # NXDOMAIN: the name doesn't exist. NoAnswer: it exists, but has no
        # record of this type. For our purposes both mean "not published".
        return []
    except dns.exception.DNSException as e:
        raise LookupFailed(f"{rdtype} {name}: {type(e).__name__}") from e


def txt(resolver, name: str) -> list[str]:
    """All TXT records at `name`, as strings."""
    out = []
    for rdata in _resolve(resolver, name, "TXT"):
        # A single TXT record can be split into several <=255-byte chunks
        # (long SPF and DKIM records usually are); they must be concatenated.
        out.append("".join(part.decode("utf-8", "replace") for part in rdata.strings))
    return out


def mx(resolver, name: str) -> list[str]:
    """MX hostnames, most preferred (lowest preference number) first.

    A "null MX" (RFC 7505, published as `0 .`) comes back as [""]: the domain
    explicitly says it accepts no mail.
    """
    records = sorted(_resolve(resolver, name, "MX"), key=lambda r: r.preference)
    return [str(r.exchange).rstrip(".").lower() for r in records]


def a(resolver, name: str) -> list[str]:
    """IPv4 addresses of `name` (CNAMEs are followed automatically)."""
    return [r.address for r in _resolve(resolver, name, "A")]


def ptr(resolver, ip: str) -> str:
    """Reverse DNS: the hostname the IP's owner has assigned to it, or "".

    1.2.3.4 is looked up as the name 4.3.2.1.in-addr.arpa. The answer is set by
    whoever controls the IP block (a hoster, an ISP), not by the domain owner,
    which is what makes it useful for identifying who runs a server.
    """
    records = _resolve(resolver, dns.reversename.from_address(ip), "PTR")
    return str(records[0].target).rstrip(".").lower() if records else ""
