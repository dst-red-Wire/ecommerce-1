"""Validate runtime WireGuard records before they enter root-owned configuration."""

import base64
import binascii
import ipaddress
import re

from ansible.errors import AnsibleFilterError


def validate_material(material, operator_pool, break_glass_pool, authorize_break_glass=False):
    """Return validated material; diagnostics must never contain runtime secrets."""
    try:

        def key(value):
            if not isinstance(value, str) or len(value) != 44:
                raise ValueError()
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
                raise ValueError()

        key(material["private_key"])
        peers = material["peers"]
        if not isinstance(peers, list) or not peers:
            raise ValueError()
        pools = {
            "workforce": ipaddress.IPv4Network(operator_pool),
            "break-glass": ipaddress.IPv4Network(break_glass_pool),
        }
        addresses, keys, identities = set(), set(), set()
        for peer in peers:
            key(peer["public_key"])
            identity = peer["identity"]
            if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}", identity):
                raise ValueError()
            scope = peer.get("scope", "workforce")
            if scope not in pools or (scope == "break-glass" and authorize_break_glass is not True):
                raise ValueError()
            raw = peer["allowed_ip"]
            if not isinstance(raw, str) or not re.fullmatch(r"[0-9.]+/32", raw):
                raise ValueError()
            address = ipaddress.IPv4Interface(raw).ip
            pool = pools[scope]
            if address not in pool or address in (pool.network_address, pool.broadcast_address):
                raise ValueError()
            if address in addresses or peer["public_key"] in keys or identity in identities:
                raise ValueError()
            addresses.add(address)
            keys.add(peer["public_key"])
            identities.add(identity)
        return material
    except (ValueError, TypeError, KeyError, binascii.Error):
        raise AnsibleFilterError("Invalid WireGuard key, identity, peer assignment or scope authorization.") from None


def fresh_handshake(text, peers, earliest):
    allowed = {peer["public_key"] for peer in peers}
    try:
        return any(
            key in allowed and int(epoch) >= earliest for key, epoch in (line.split() for line in text.splitlines())
        )
    except (ValueError, TypeError):
        return False


class FilterModule:
    def filters(self):
        return {"mgmt_wireguard_material": validate_material, "mgmt_wireguard_fresh_handshake": fresh_handshake}
