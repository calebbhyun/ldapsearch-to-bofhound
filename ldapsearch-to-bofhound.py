#!/usr/bin/env python3
"""
Convert `ldapsearch` (LDIF) output into **BOFHound**-compatible format.

Example:

    # 1) Collect from LDAP
    ldapsearch -LLL \
      -E pr=10000/noprompt \
      -E '!1.2.840.113556.1.4.801=::MAMCAQc=' \
      -o ldif-wrap=no \
      -H ldap://10.0.0.1:389 \
      -x -D 'domainuser@corp.local' -w 'password' \
      -b 'DC=corp,DC=local' \
      '(objectclass=*)' '*' nTSecurityDescriptor \
      | tee ldapsearch_all.out

    # 2) Convert to BOFHound-compatible format.
    python3 ldapsearch-to-bofhound.py ldapsearch_all.txt all.bofhound

    # 3) Feed into BOFHound
    bofhound -i all.bofhound
"""
import argparse
import base64
import struct

# ---------- Decoders for important attributes ----------
def decode_sid(encoded: str) -> str:
    """Decode a base64-encoded SID into S-1-5-... form."""
    try:
        data = base64.b64decode(encoded)
    except Exception:
        return encoded

    if len(data) < 8:
        return encoded

    revision = data[0]
    identifier_authority = int.from_bytes(data[2:8], "big")
    sub_auths = [
        str(int.from_bytes(data[i:i + 4], "little"))
        for i in range(8, len(data), 4)
    ]
    return f"S-{revision}-{identifier_authority}" + "".join(f"-{sa}" for sa in sub_auths)

def decode_guid(encoded: str) -> str:
    """Decode a base64-encoded GUID into XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX form."""
    try:
        raw = base64.b64decode(encoded)
        parts = struct.unpack("<IHHBBBBBBBB", raw)
    except Exception:
        return encoded

    return (
        f"{parts[0]:08x}-{parts[1]:04x}-{parts[2]:04x}-"
        f"{parts[3]:02x}{parts[4]:02x}-"
        f"{parts[5]:02x}{parts[6]:02x}{parts[7]:02x}"
        f"{parts[8]:02x}{parts[9]:02x}{parts[10]:02x}"
    ).lower()

def decode_generic_bytes(encoded: str) -> str:
    """
    Decode base64-encoded opaque binary data to a Python b'\\x..' style string.
    BOFHound expects this representation for several binary attributes.
    """
    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return encoded

    hex_bytes = "".join(f"\\x{b:02x}" for b in raw)
    return f"b'{hex_bytes}'"

def decode_dns_records(encoded_list: str) -> str:
    """
    Decode base64-encoded DNS records (dnsRecord attribute).

    ldapsearch typically shows this as:
        [BASE64, BASE64, ...]

    We convert each element to a b'...' string with printable ASCII where possible.
    """
    encoded_list = encoded_list.strip()

    # Single value (no brackets) vs list
    if encoded_list.startswith("[") and encoded_list.endswith("]"):
        inner = encoded_list[1:-1]
        values = [v.strip() for v in inner.split(",") if v.strip()]
    else:
        values = [encoded_list] if encoded_list else []

    decoded_pieces = []
    for v in values:
        try:
            raw = base64.b64decode(v)
        except Exception:
            decoded_pieces.append(f"Error decoding: {v}")
            continue

        s = "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in raw)
        decoded_pieces.append(f"b'{s}'")

    return "[" + ", ".join(decoded_pieces) + "]"

# Map attribute name -> decode function. Case-sensitive to match AD attribute names.
DECODERS = {
    "objectSid": decode_sid,
    "securityIdentifier": decode_sid,  # needed for trustedDomain objects / domain trusts
    "objectGUID": decode_guid,
    "dnsRecord": decode_dns_records,
    # Various binary GUID / blob-ish attrs that BOFHound likes as b'\\x..'
    "msDFSR-ContentSetGuid": decode_generic_bytes,
    "msDFSR-ReplicationGroupGuid": decode_generic_bytes,
    "mS-DS-ConsistencyGuid": decode_generic_bytes,
    "samDomainUpdates": decode_generic_bytes,
    # If you care about key credential parsing, you can add special handling;
    # otherwise generic bytes is usually fine:
    "msDS-KeyCredentialLink": decode_generic_bytes,
}

# ---------- LDIF parsing helpers ----------
REMOVE_PREFIXES = ("dn: ", "ref: ", "result: ", "search: ")

def line_should_be_dropped(line: str) -> bool:
    """Return True if this LDIF line is boilerplate/control we don't want in BOFHound logs."""
    stripped = line.strip()
    return (
        not stripped
        or stripped.startswith("#")
        or any(stripped.startswith(p) for p in REMOVE_PREFIXES)
    )

def process_attr_line(line: str) -> str:
    """
    Convert an LDIF attribute line into "attr: value" with decoding.

    Handles:
        attr: value
        attr:: base64value
    """
    line = line.rstrip("\n")

    # Base64 value
    if "::" in line:
        attr, encoded = line.split("::", 1)
        attr = attr.strip()
        encoded = encoded.strip()
        decoder = DECODERS.get(attr)
        value = decoder(encoded) if decoder else encoded
        return f"{attr}: {value}"

    # Normal, non-base64 line "attr: value"
    if ": " in line:
        attr, value = line.split(": ", 1)
        return f"{attr.strip()}: {value.strip()}"

    # Something unexpected – just pass through
    return line

def process_object(block: str) -> str:
    """
    Convert a single LDIF entry (separated by blank lines) into BOFHound-style lines.

    - Drop boilerplate/control lines
    - Apply decoding to relevant attributes
    - Collapse duplicate attributes into comma-separated lists, e.g.
        memberOf: A
        memberOf: B
      -> memberOf: A, B
    """
    attrs: dict[str, list[str]] = {}

    for raw_line in block.splitlines():
        if line_should_be_dropped(raw_line):
            continue

        converted = process_attr_line(raw_line)
        if ": " not in converted:
            continue

        attr, value = converted.split(": ", 1)
        attrs.setdefault(attr, []).append(value)

    lines = [f"{attr}: {', '.join(values)}" for attr, values in attrs.items()]
    return "\n".join(lines)

def convert_ldif_to_bofhound(input_path: str, output_path: str) -> None:
    """Read ldapsearch LDIF from input_path and write BOFHound-compatible log to output_path."""
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # ldapsearch -LLL separates entries by a blank line
    raw_objects = content.split("\n\n")

    pieces: list[str] = []
    for obj in raw_objects:
        if not obj.strip():
            continue

        # If every line in the object is "drop", skip it
        lines = obj.splitlines()
        if all(line_should_be_dropped(l) for l in lines):
            continue

        body = process_object(obj)
        if not body.strip():
            continue

        pieces.append("--------------------\n" + body)

    out_data = "\n".join(pieces)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(out_data)

# ---------- CLI ----------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Linux ldapsearch output (LDIF) to BOFHound-compatible log format."
    )
    parser.add_argument("input_file", help="Path to ldapsearch LDIF output")
    parser.add_argument("output_file", help="Path to write BOFHound-style log")

    args = parser.parse_args()
    convert_ldif_to_bofhound(args.input_file, args.output_file)

if __name__ == "__main__":
    main()
