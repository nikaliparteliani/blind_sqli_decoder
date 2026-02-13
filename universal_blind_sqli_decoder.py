#!/usr/bin/env python3
"""
Universal Blind SQL Injection Decoder
======================================
ნებისმიერი pcap/pcapng ფაილიდან blind SQLi შეტევის
ავტომატური აღმოჩენა და ექსტრაქტირებული მონაცემების რეკონსტრუქცია.

მხარდაჭერილი:
  - Boolean-based blind (ORD/ASCII/UNICODE + MID/SUBSTRING/SUBSTR)
  - AND, OR, AND NOT, OR NOT ინექციები
  - ავტომატური TRUE/FALSE პოლარობის დეტექტირება (dual-polarity)
  - Binary search + equality-based ექსტრაქცია
  - pcap და pcapng ფორმატები
  - HTTP ნებისმიერ პორტზე (ავტო-დეტექტირება)
  - GET და POST რექვესტები
  - Time-based blind SQLi დეტექტირება
  - MD5 ჰეშების ავტომატური გატეხვა

გამოყენება:
  python3 universal_blind_sqli_decoder.py <capture_file>
  python3 universal_blind_sqli_decoder.py capture.pcapng --port 80
  python3 universal_blind_sqli_decoder.py capture.pcapng --verbose
"""

import struct
import sys
import re
import argparse
from urllib.parse import unquote, unquote_plus
from collections import defaultdict, Counter


# ═══════════════════════════════════════════════════════════════════
#  1. pcap / pcapng პარსერი
# ═══════════════════════════════════════════════════════════════════

def parse_capture_file(filepath):
    """pcap ან pcapng ფაილიდან პაკეტების ამოღება + timestamps."""
    with open(filepath, "rb") as f:
        data = f.read()

    magic = struct.unpack("<I", data[:4])[0]

    if magic == 0x0A0D0D0A:
        return _parse_pcapng(data)
    elif magic in (0xA1B2C3D4, 0xD4C3B2A1):
        return _parse_pcap(data)
    else:
        print(f"[!] უცნობი ფორმატი (magic: 0x{magic:08X})")
        sys.exit(1)


def _parse_pcapng(data):
    packets = []
    pos = 0
    ts_resolutions = {}
    iface_idx = 0

    while pos + 8 <= len(data):
        block_type = struct.unpack("<I", data[pos:pos + 4])[0]
        block_len  = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        if block_len < 12 or pos + block_len > len(data):
            break
        body = data[pos + 8 : pos + block_len - 4]

        if block_type == 0x00000001:   # Interface Description Block
            ts_resolutions[iface_idx] = 1_000_000
            opt_pos = 8
            while opt_pos + 4 <= len(body):
                oc = struct.unpack("<H", body[opt_pos:opt_pos + 2])[0]
                ol = struct.unpack("<H", body[opt_pos + 2:opt_pos + 4])[0]
                if oc == 0:
                    break
                if oc == 9 and ol >= 1:
                    tb = body[opt_pos + 4]
                    ts_resolutions[iface_idx] = (
                        2 ** (tb & 0x7F) if tb & 0x80 else 10 ** tb
                    )
                opt_pos += 4 + ((ol + 3) & ~3)
            iface_idx += 1

        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                epb_iface    = struct.unpack("<I", body[0:4])[0]
                ts_high      = struct.unpack("<I", body[4:8])[0]
                ts_low       = struct.unpack("<I", body[8:12])[0]
                captured_len = struct.unpack("<I", body[12:16])[0]
                ts_raw = (ts_high << 32) | ts_low
                res = ts_resolutions.get(epb_iface, 1_000_000)
                packets.append((ts_raw / res, body[20:20 + captured_len]))

        pos += block_len

    return packets


def _parse_pcap(data):
    packets = []
    magic = struct.unpack("<I", data[:4])[0]
    big = magic == 0xD4C3B2A1
    fmt = ">" if big else "<"
    pos = 24

    while pos + 16 <= len(data):
        ts_sec  = struct.unpack(f"{fmt}I", data[pos:pos + 4])[0]
        ts_usec = struct.unpack(f"{fmt}I", data[pos + 4:pos + 8])[0]
        incl    = struct.unpack(f"{fmt}I", data[pos + 8:pos + 12])[0]
        pos += 16
        if pos + incl > len(data):
            break
        packets.append((ts_sec + ts_usec / 1e6, data[pos:pos + incl]))
        pos += incl

    return packets


# ═══════════════════════════════════════════════════════════════════
#  2. TCP სტრიმები → HTTP წყვილები
# ═══════════════════════════════════════════════════════════════════

def _tcp_info(pkt):
    """Ethernet → IPv4 → TCP ინფორმაციის ამოღება."""
    if len(pkt) < 34:
        return None

    offset = 14
    etype = struct.unpack(">H", pkt[12:14])[0]
    # VLAN tag-ების გამოტოვება
    while etype in (0x8100, 0x88A8, 0x9100):
        if offset + 4 > len(pkt):
            return None
        etype = struct.unpack(">H", pkt[offset + 2:offset + 4])[0]
        offset += 4

    if etype != 0x0800:
        return None
    if offset + 20 > len(pkt):
        return None
    if pkt[offset + 9] != 6:  # TCP
        return None

    ihl = (pkt[offset] & 0x0F) * 4
    tcp = offset + ihl
    if tcp + 20 > len(pkt):
        return None

    doff = ((pkt[tcp + 12] >> 4) * 4)
    return {
        "sp": struct.unpack(">H", pkt[tcp:tcp + 2])[0],
        "dp": struct.unpack(">H", pkt[tcp + 2:tcp + 4])[0],
        "fl": pkt[tcp + 13],
        "pl": pkt[tcp + doff:],
    }


def detect_http_port(packets):
    """HTTP პორტის ავტო-დეტექტირება."""
    scores = Counter()
    for _, pkt in packets:
        info = _tcp_info(pkt)
        if not info or not info["pl"]:
            continue
        p = info["pl"]
        if p[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"PATC", b"DELE"):
            scores[info["dp"]] += 1
        if p[:5] == b"HTTP/":
            scores[info["sp"]] += 1
    return scores.most_common(1)[0][0] if scores else None


def build_http_pairs(packets, server_port):
    """TCP კონექშენები → HTTP request/response წყვილები (port reuse safe)."""
    port_cid = defaultdict(int)
    active = {}
    conns = {}

    for ts, pkt in packets:
        info = _tcp_info(pkt)
        if not info:
            continue
        sp, dp, fl, pl = info["sp"], info["dp"], info["fl"], info["pl"]

        # SYN-only → ახალი კონექშენი
        if dp == server_port and (fl & 0x02) and not (fl & 0x10):
            port_cid[sp] += 1
            active[sp] = port_cid[sp]
            conns[(sp, port_cid[sp])] = {"req": b"", "resp": b""}
            continue

        if not pl:
            continue

        if dp == server_port:
            k = (sp, active.get(sp, port_cid.get(sp, 1) or 1))
            if k not in conns:
                conns[k] = {"req": b"", "resp": b""}
            conns[k]["req"] += pl
        elif sp == server_port:
            k = (dp, active.get(dp, port_cid.get(dp, 1) or 1))
            if k not in conns:
                conns[k] = {"req": b"", "resp": b""}
            conns[k]["resp"] += pl

    pairs = []
    for key in sorted(conns):
        c = conns[key]
        req  = c["req"].decode("utf-8", errors="replace")
        resp = c["resp"].decode("utf-8", errors="replace")
        if not req.strip():
            continue
        status = 0
        m = re.search(r"HTTP/\d\.\d\s+(\d{3})", resp)
        if m:
            status = int(m.group(1))
        pairs.append({"req": req, "resp": resp, "status": status})

    return pairs


# ═══════════════════════════════════════════════════════════════════
#  3. Blind SQLi regex ნიმუშები
# ═══════════════════════════════════════════════════════════════════

# ფორმატი 1: ORD(MID((SELECT ...), pos, 1)) > threshold
RE_BLIND = re.compile(
    r"(?:AND|OR)\s+(NOT\s+)?"
    r"(?:ORD|ASCII|UNICODE)\s*\(\s*"
    r"(?:MID|SUBSTRING|SUBSTR)\s*\(\s*"
    r"\(\s*(SELECT\s+.+?)\s*\)"    # SELECT expression
    r"\s*,\s*(\d+)"                 # position
    r"\s*,\s*1\s*\)\s*\)"
    r"\s*([><=!]+)\s*"              # operator
    r"(\d+)",                       # threshold
    re.IGNORECASE | re.DOTALL,
)

# ფორმატი 2: SELECT ფრჩხილებში
RE_BLIND_ALT = re.compile(
    r"(?:AND|OR)\s+(NOT\s+)?"
    r"(?:ORD|ASCII|UNICODE)\s*\(\s*"
    r"(?:MID|SUBSTRING|SUBSTR)\s*\(\s*"
    r"(\(SELECT\s+.+?\))"          # SELECT with own parens
    r"\s*,\s*(\d+)"                 # position
    r"\s*,\s*1\s*\)"
    r"\s*([><=!]+)\s*"              # operator
    r"(\d+)",                       # threshold
    re.IGNORECASE | re.DOTALL,
)

RE_LIMIT  = re.compile(r"LIMIT\s+(\d+)\s*,\s*1", re.IGNORECASE)
RE_OFFSET = re.compile(r"OFFSET\s+(\d+)", re.IGNORECASE)

RE_TIME_BASED = re.compile(
    r"(?:SLEEP|WAITFOR\s+DELAY|BENCHMARK|pg_sleep)\s*\(", re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════
#  4. დამხმარე ფუნქციები
# ═══════════════════════════════════════════════════════════════════

def _get_url(req):
    line = req.split("\r\n")[0] if "\r\n" in req else req.split("\n")[0]
    parts = line.split(" ")
    return parts[1] if len(parts) >= 2 else ""


def _get_resp_body(resp):
    for sep in ["\r\n\r\n", "\n\n"]:
        i = resp.find(sep)
        if i >= 0:
            return resp[i + len(sep):]
    return resp


def _get_post_data(req):
    i = req.find("\r\n\r\n")
    return req[i + 4:] if i >= 0 else ""


def _extract_target(expr):
    """SELECT expression → 'table.column' სტრინგი."""
    cm = re.search(r"COUNT\(\s*(?:DISTINCT\s*\(?\s*)?(\w+|\*)\s*\)?\s*\)", expr, re.I)
    if cm:
        col = f"COUNT({cm.group(1)})"
    else:
        cm2 = re.search(r"(?:CAST\()?(\w+)\s+AS\s+", expr, re.I)
        if not cm2:
            cm2 = re.search(r"SELECT\s+(\w+)", expr, re.I)
        col = cm2.group(1) if cm2 else "?"

    fm = re.search(r"FROM\s+([\w.`\"]+)", expr, re.I)
    table = fm.group(1).strip("`\"") if fm else "?"

    return f"{table}.{col}"


def _extract_row(expr):
    m = RE_LIMIT.search(expr)
    if m:
        return int(m.group(1))
    m = RE_OFFSET.search(expr)
    if m:
        return int(m.group(1))
    return 0


NEGATE = {">": "<=", ">=": "<", "<": ">=", "<=": ">",
          "=": "!=", "!=": "=", "<>": "="}


# ═══════════════════════════════════════════════════════════════════
#  5. შედარებების ექსტრაქცია
# ═══════════════════════════════════════════════════════════════════

def extract_raw_comparisons(pairs):
    """HTTP წყვილებიდან raw შედარებების ამოღება (TRUE/FALSE ჯერ არ ვადგენთ)."""
    records = []
    time_count = 0

    for pair in pairs:
        url  = _get_url(pair["req"])
        post = _get_post_data(pair["req"])
        resp_body = _get_resp_body(pair["resp"]).strip()

        for raw in [url, post]:
            if not raw.strip():
                continue
            decoded = unquote(unquote_plus(raw))

            if RE_TIME_BASED.search(decoded):
                time_count += 1

            for regex in [RE_BLIND, RE_BLIND_ALT]:
                for m in regex.finditer(decoded):
                    has_not    = bool(m.group(1) and m.group(1).strip())
                    select_expr = m.group(2)
                    position   = int(m.group(3))
                    op_raw     = m.group(4).strip()
                    threshold  = int(m.group(5))

                    target = _extract_target(select_expr)
                    row    = _extract_row(select_expr)

                    # NOT-ის გათვალისწინება ოპერატორში
                    eff_op = NEGATE.get(op_raw, op_raw) if has_not else op_raw

                    records.append({
                        "target": target,
                        "row": row,
                        "pos": position,
                        "eff_op": eff_op,
                        "threshold": threshold,
                        "resp_fp": resp_body,
                    })

    return records, time_count


# ═══════════════════════════════════════════════════════════════════
#  6. ავტო-პოლარობა + სიმბოლოების რეკონსტრუქცია
# ═══════════════════════════════════════════════════════════════════

def _resolve_char(ops):
    """Binary search ოპერაციებიდან სიმბოლოს მნიშვნელობის დადგენა."""
    lo, hi, exact = -1, 256, None

    for op, threshold, is_true in ops:
        if op == ">" and is_true:
            lo = max(lo, threshold)
        elif op == ">" and not is_true:
            hi = min(hi, threshold)
        elif op == "<=" and is_true:
            hi = min(hi, threshold)
        elif op == "<=" and not is_true:
            lo = max(lo, threshold)
        elif op == "<" and is_true:
            hi = min(hi, threshold - 1)
        elif op == "<" and not is_true:
            lo = max(lo, threshold - 1)
        elif op == ">=" and is_true:
            lo = max(lo, threshold - 1)
        elif op == ">=" and not is_true:
            hi = min(hi, threshold - 1)
        elif op == "=" and is_true:
            exact = threshold
        elif op == "!=" and not is_true:
            exact = threshold

    if exact is not None:
        return exact
    if 0 <= hi - lo <= 1:
        return hi
    if lo >= 0:
        return lo + 1
    return None


def _try_polarity(records, fp_true_set):
    """
    მოცემული პოლარობით (fp_true_set = fingerprints that mean TRUE)
    შედეგების რეკონსტრუქცია.
    აბრუნებს (data_dict, printable_ascii_ratio).
    """
    grouped = defaultdict(list)

    for rec in records:
        is_true = rec["resp_fp"] in fp_true_set
        key = (rec["target"], rec["row"], rec["pos"])
        grouped[key].append((rec["eff_op"], rec["threshold"], is_true))

    result = defaultdict(lambda: defaultdict(dict))
    printable = 0
    total = 0

    for (target, row, pos), ops in grouped.items():
        val = _resolve_char(ops)
        if val is None:
            continue
        total += 1
        if 32 <= val <= 126:
            printable += 1
        if 0 < val < 256:
            result[target][row][pos] = chr(val)

    # სტრინგების აწყობა
    data = {}
    for target in sorted(result):
        data[target] = {}
        for row in sorted(result[target]):
            positions = result[target][row]
            if not positions:
                continue
            mx = max(positions.keys())
            data[target][row] = "".join(
                positions.get(p, "\u2591") for p in range(1, mx + 1)
            )

    ratio = printable / max(total, 1)
    return data, ratio


def reconstruct_with_auto_polarity(records):
    """
    ორივე პოლარობას ვცდით (რომელი fingerprint = TRUE)
    და ვირჩევთ იმას, რომელიც მეტ printable ASCII-ს იძლევა.
    ეს უნივერსალურია: AND, OR, NOT — ნებისმიერ კომბინაციაზე მუშაობს.
    """
    all_fps = set(rec["resp_fp"] for rec in records)

    if len(all_fps) < 2:
        # მხოლოდ 1 ტიპის რესპონსი
        data, _ = _try_polarity(records, all_fps)
        return data

    # ორი ყველაზე ხშირი fingerprint
    fp_counts = Counter(rec["resp_fp"] for rec in records)
    top = fp_counts.most_common()
    fp_a = top[0][0]
    fp_b = top[1][0]

    # პოლარობა A: fp_a = TRUE
    set_a = {fp_a}
    data_a, ratio_a = _try_polarity(records, set_a)

    # პოლარობა B: fp_b = TRUE (ყველაფერი fp_a-ს გარდა)
    set_b = all_fps - {fp_a}
    data_b, ratio_b = _try_polarity(records, set_b)

    # ვირჩევთ უკეთესს: მეტი printable ASCII = სწორი პოლარობა
    if ratio_a >= ratio_b:
        chosen, pct = "A", ratio_a
        result = data_a
    else:
        chosen, pct = "B", ratio_b
        result = data_b

    print(f"    პოლარობა {chosen} არჩეულია (printable ASCII: {pct:.1%})")

    return result


# ═══════════════════════════════════════════════════════════════════
#  7. MD5 ჰეშების გატეხვა
# ═══════════════════════════════════════════════════════════════════

COMMON_MD5 = {
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e99a18c428cb38d5f260853678922e03": "abc123",
    "8d3533d75ae2c3966d7e0d4fcc69216b": "charley",
    "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "25d55ad283aa400af464c76d713c07ad": "12345678",
    "827ccb0eea8a706c4c34a16891f84e7b": "12345",
    "202cb962ac59075b964b07152d234b70": "123",
    "21232f297a57a5a743894a0e4a801fc3": "admin",
    "ee11cbb19052e40b07aac5ae8c4e8402": "user",
    "5d41402abc4b2a76b9719d911017c592": "hello",
    "f25a2fc72690b780b2a14e140ef6a9e0": "iloveyou",
    "25f9e794323b453885f5181f1b624d0b": "123456789",
    "d577273ff885c3f84dadb8578bb41399": "football",
    "96e79218965eb72c92a549dd5a330112": "111111",
    "fcea920f7412b5da7be0cf42b8c93759": "1234567",
    "81dc9bdb52d04dc20036dbd8313ed055": "1234",
    "c33367701511b4f6020ec61ded352059": "654321",
    "d0763edaa9d9bd2a9516280e9044d885": "monkey",
    "b25ef06be3b6948c0bc431da46c2c738": "shadow",
    "7c6a180b36896a65c4c202c1121e1382": "1q2w3e",
}

MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def crack_hashes(data):
    cracked = {}
    for target, rows in data.items():
        for row, value in rows.items():
            v = value.strip()
            if MD5_RE.match(v):
                h = v.lower()
                if h in COMMON_MD5:
                    cracked[(target, row, v)] = COMMON_MD5[h]
    return cracked


# ═══════════════════════════════════════════════════════════════════
#  8. გამოტანა
# ═══════════════════════════════════════════════════════════════════

def print_results(data, cracked, time_count, verbose):
    if not data:
        print("\n[!] Blind SQLi ექსტრაქცია ვერ მოიძებნა.")
        if time_count:
            print(f"[*] Time-based SQLi მინიშნებები: {time_count}")
        return

    # ცხრილებად დაჯგუფება
    tables = defaultdict(lambda: defaultdict(dict))
    counts = {}

    for target, rows in data.items():
        parts = target.rsplit(".", 1)
        table = parts[0] if len(parts) == 2 else "unknown"
        col   = parts[1] if len(parts) == 2 else target

        if col.startswith("COUNT("):
            for row, val in rows.items():
                counts[f"{col} FROM {table}"] = val
        else:
            for row, val in rows.items():
                tables[table][col][row] = val

    # COUNT-ები
    if counts:
        print()
        _section("COUNT ექსტრაქციები")
        for label, val in sorted(counts.items()):
            print(f"  {label} = {val}")

    # ცხრილები
    for table in sorted(tables):
        cols = tables[table]
        all_cols = sorted(cols.keys())
        all_rows = sorted(set(r for cd in cols.values() for r in cd))
        if not all_rows:
            continue

        print()
        _section(table)

        # სვეტის სიგანეები
        widths = {}
        for c in all_cols:
            mx = max((len(cols[c].get(r, "")) for r in all_rows), default=0)
            widths[c] = max(len(c), mx, 4) + 2

        hdr = f"  {'#':<5}" + "".join(f"{c:<{widths[c]}}" for c in all_cols)
        print(hdr)
        print("  " + "─" * (5 + sum(widths.values())))

        for row in all_rows:
            line = f"  {row:<5}"
            notes = ""
            for c in all_cols:
                v = cols[c].get(row, "")
                line += f"{v:<{widths[c]}}"
                key = (f"{table}.{c}", row, v)
                if key in cracked:
                    notes += f"  ← {c}: \"{cracked[key]}\""
            print(line + notes)

    # FLAG / საინტერესო მონაცემები
    print()
    _section("FLAG / საინტერესო მონაცემები")
    found = False

    flag_pats = [
        re.compile(r"(?:flag|ctf|dga|htb|thm|pico|asis|dctf)\{[^}]+\}", re.I),
        re.compile(r"(?:password|secret|key|token|api.?key)\s*[:=]\s*\S+", re.I),
    ]

    for target, rows in data.items():
        for row, val in rows.items():
            for pat in flag_pats:
                m = pat.search(val)
                if m:
                    print(f"  [{target} row {row}] {m.group(0)}")
                    found = True

    if cracked:
        found = True
        print()
        print("  გატეხილი MD5 ჰეშები:")
        for (t, r, h), pw in cracked.items():
            print(f"    [{t} row {r}] {h} → \"{pw}\"")

    if not found:
        print("  (ავტომატურად ვერ მოიძებნა)")

    if time_count:
        print(f"\n  [*] Time-based SQLi: {time_count} მინიშნება")


def _section(title):
    w = max(len(title) + 4, 50)
    print("─" * w)
    print(f"  {title}")
    print("─" * w)


# ═══════════════════════════════════════════════════════════════════
#  9. main
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Universal Blind SQL Injection Decoder",
    )
    parser.add_argument("capture_file", help="pcap / pcapng ფაილი")
    parser.add_argument("--port", type=int, default=0,
                        help="HTTP პორტი (0 = ავტო)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print("  Universal Blind SQL Injection Decoder")
    print("=" * 60)

    # 1. ფაილი
    print(f"\n[1] ფაილი: {args.capture_file}")
    packets = parse_capture_file(args.capture_file)
    print(f"    პაკეტები: {len(packets):,}")
    if not packets:
        print("[!] ცარიელი ფაილი.")
        sys.exit(1)

    # 2. HTTP პორტი
    if args.port:
        port = args.port
    else:
        print("\n[2] HTTP პორტის ავტო-დეტექტირება...")
        port = detect_http_port(packets)
        if not port:
            print("[!] HTTP ტრაფიკი ვერ მოიძებნა.")
            sys.exit(1)
    print(f"    პორტი: {port}")

    # 3. TCP → HTTP
    print(f"\n[3] TCP სტრიმების აწყობა (port reuse safe)...")
    pairs = build_http_pairs(packets, port)
    print(f"    HTTP წყვილები: {len(pairs):,}")
    if not pairs:
        print("[!] HTTP წყვილები ვერ მოიძებნა.")
        sys.exit(1)

    # 4. Blind SQLi ამოღება
    print(f"\n[4] Blind SQLi შედარებების ამოღება...")
    records, time_count = extract_raw_comparisons(pairs)
    print(f"    Boolean-based შედარებები: {len(records):,}")
    if time_count:
        print(f"    Time-based მინიშნებები: {time_count}")
    if not records and not time_count:
        print("[!] Blind SQLi ვერ აღმოჩნდა.")
        sys.exit(0)

    # 5. ავტო-პოლარობა + რეკონსტრუქცია
    print(f"\n[5] ავტო-პოლარობის დეტექტირება + სიმბოლოების აღდგენა...")
    data = reconstruct_with_auto_polarity(records)
    total = sum(len(v) for rows in data.values() for v in rows.values())
    print(f"    აღდგენილი სიმბოლოები: {total:,}")

    if args.verbose:
        targets = sorted(set(r["target"] for r in records))
        print(f"\n    სამიზნეები ({len(targets)}):")
        for t in targets:
            cnt = sum(1 for r in records if r["target"] == t)
            print(f"      {t}: {cnt} შედარება")

    # 6. MD5 გატეხვა
    cracked = crack_hashes(data)

    # 7. შედეგები
    print_results(data, cracked, time_count, args.verbose)
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
