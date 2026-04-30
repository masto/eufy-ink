#!/usr/bin/env python3
"""
Read the live ink levels from an eufyMake UV Printer E1 by talking to
Anker's MQTT broker the same way the desktop app does, decrypting the
AES-256-CBC payloads, and picking the `leftInk` array out of the
commandType-1100 status message.

Credentials are loaded from the desktop app's on-disk cache
(~/Library/Application Support/eufyMake Studio Profile/), so you only
have to sign in once; the app can then be closed.

See README.md for the protocol reference. In short:

  * TLS MQTT to make-mqtt.ankermake.com:8789
      username   eufy_<user_id>
      password   <URL-decoded email>
      client id  pc_macos_AnkerMakeStudio_direct_<user_id>_<rand>_<ts>
  * Subscribe to the five /phone/maker/<sn>/… and /phone/user/<uid>/…
    topics (broker ACL refuses wildcard subscriptions).
  * Publish {"commandType": 1027, "value": 0} to /device/maker/<sn>/query.
    The printer responds with an ack on /phone/maker/<sn>/command/reply
    and then a big batched notice on /phone/maker/<sn>/notice that has
    the ink state as a commandType-1100 item.

Usage:
  python3 eufy_ink.py                 # one shot
  python3 eufy_ink.py --watch         # stay connected, print every update
  python3 eufy_ink.py --raw           # dump every decrypted item as JSON
  python3 eufy_ink.py --dump DIR      # save raw encrypted frames for replay
  python3 eufy_ink.py --from-file P   # decode a saved raw frame offline

Protocol credits:
  https://charliex2.wordpress.com/2026/03/06/eufy/
  https://github.com/Django1982/ankerctl_go_remake/
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

BROKERS = {
    "US": "make-mqtt.ankermake.com",
    "CA": "make-mqtt.ankermake.com",
    "MX": "make-mqtt.ankermake.com",
    "EU": "make-mqtt-eu.ankermake.com",
    "GB": "make-mqtt-eu.ankermake.com",
    "DE": "make-mqtt-eu.ankermake.com",
    "FR": "make-mqtt-eu.ankermake.com",
}
DEFAULT_BROKER = "make-mqtt.ankermake.com"
BROKER_PORT = 8789

CBC_IV = b"3DPrintAnkerMake"  # fixed, 16 bytes

APP_CERT_CANDIDATES = [
    "/Applications/eufyMake Studio.app/Contents/MacOS/make-us.crt",
    "/Applications/eufyMake Studio.app/Contents/MacOS/make-us-qa.crt",
    "/Applications/AnkerMake Studio.app/Contents/MacOS/make-us.crt",
]

PROFILE_CANDIDATES = [
    "~/Library/Application Support/eufyMake Studio Profile",  # macOS
    "~/AppData/Roaming/eufyMake Studio Profile",  # Windows
    "~/.config/eufyMake Studio Profile",  # Linux
    "~/Library/Application Support/AnkerMake Studio Profile",  # legacy
]

INK_CHANNELS = [
    ("C", "cyan"),
    ("M", "magenta"),
    ("Y", "yellow"),
    ("K", "black"),
    ("W", "white"),
    ("G", "gloss"),
]

# commandType values we care about (there are many more; all >= 1000).
CMD_INK_STATUS = 1100  # printer broadcast with ink + waste-tank levels
CMD_APP_QUERY_STATUS = 1027  # "phone just connected, push me everything"

log = logging.getLogger("eufy_ink")


# --------------------------------------------------------------------------
# Config loader (reads the desktop app's profile cache)
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Cfg:
    user_id: str
    email: str  # URL-decoded, used as the MQTT password
    ab_code: str
    station_sn: str
    secret_key: bytes


def _find_profile() -> Path:
    override = os.environ.get("EUFY_PROFILE_DIR")
    roots = [override] + PROFILE_CANDIDATES if override else PROFILE_CANDIDATES
    for raw in roots:
        p = Path(os.path.expanduser(raw))
        if (p / "cache/offline/device_info/device_list.json").exists():
            return p
    raise SystemExit(
        "couldn't find the eufyMake Studio profile directory; sign in to "
        "the desktop app once, or set EUFY_PROFILE_DIR."
    )


def load_cfg(device_index: int = 0) -> Cfg:
    profile = _find_profile()
    dl = json.loads(
        (profile / "cache/offline/device_info/device_list.json").read_text()
    )
    li = json.loads((profile / "cache/offline/user_info/login_info.json").read_text())
    devices = dl.get("data") or []
    if device_index >= len(devices):
        raise SystemExit(
            f"--device-index {device_index} out of range "
            f"(have {len(devices)} devices)"
        )
    dev = devices[device_index]
    data = li.get("data") or {}
    sk_hex = dev["secret_key"]
    if len(sk_hex) != 64:
        raise SystemExit(f"unexpected secret_key length {len(sk_hex)}")
    return Cfg(
        user_id=data["user_id"],
        email=urllib.parse.unquote(data.get("email", "")),
        ab_code=data.get("ab_code") or "US",
        station_sn=dev["station_sn"],
        secret_key=bytes.fromhex(sk_hex),
    )


# --------------------------------------------------------------------------
# Wire format: 'MA'/'MB' header + AES-256-CBC + XOR checksum
# --------------------------------------------------------------------------


def _pkcs7_pad(data: bytes) -> bytes:
    p = PKCS7(128).padder()
    return p.update(data) + p.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    u = PKCS7(128).unpadder()
    return u.update(data) + u.finalize()


def _xor(data: bytes) -> int:
    x = 0
    for b in data:
        x ^= b
    return x


@dataclasses.dataclass
class Frame:
    magic: str  # "MA" or "MB"
    size: int
    header_size: int  # 24 (M5=6 / M5=1) or 64 (M5=2); +2 for 'MB'
    m5: int  # header variant byte: 1=M5C, 2=M5 (app), 6=UV printer broadcast
    packet_type: int  # 0xC0 = single, 0xC1..C3 = fragmented
    packet_num: int
    timestamp: int  # unix seconds; populated when M5=2 (and in practice for M5=6 too)
    ciphertext: bytes
    checksum_ok: bool
    raw: bytes


def parse_frame(wire: bytes) -> Frame:
    if len(wire) < 12:
        raise ValueError(f"frame too short: {len(wire)} bytes")
    magic = wire[:2]
    if magic == b"MA":
        size = int.from_bytes(wire[2:4], "little")
        size_bytes = 2
    elif magic == b"MB":
        size = int.from_bytes(wire[2:6], "little")
        size_bytes = 4
    else:
        raise ValueError(f"bad magic {magic!r}")
    if size != len(wire):
        raise ValueError(f"size field {size} != wire len {len(wire)}")

    m5 = wire[2 + size_bytes + 2]  # byte index [6] for MA, [8] for MB
    packet_type = wire[2 + size_bytes + 5]
    packet_num = int.from_bytes(wire[2 + size_bytes + 6 : 2 + size_bytes + 8], "little")
    timestamp = int.from_bytes(wire[2 + size_bytes + 8 : 2 + size_bytes + 12], "little")

    # Header length depends on the M5 variant:
    #   M5 = 2       -> 64 bytes (3D printer/desktop-app "M5" format)
    #   M5 = 1 or 6  -> 24 bytes ("M5C" / UV printer broadcast format)
    header_len = (64 if m5 == 2 else 24) + (size_bytes - 2)

    return Frame(
        magic=magic.decode(),
        size=size,
        header_size=header_len,
        m5=m5,
        packet_type=packet_type,
        packet_num=packet_num,
        timestamp=timestamp,
        ciphertext=wire[header_len:-1],
        checksum_ok=_xor(wire[:-1]) == wire[-1],
        raw=wire,
    )


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(CBC_IV)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return _pkcs7_unpad(padded)


def build_app_frame(key: bytes, plaintext: bytes) -> bytes:
    """Build an 'MA' (or 'MB') frame in the format the desktop app sends.

    This is the 64-byte "M5" variant with a random DeviceGUID in the 37-byte
    C-string slot. The printer will only respond to commands wrapped this
    way; the shorter 24-byte variant (which the printer itself emits) is
    silently dropped. Matches the default packet layout in
    ankerctl_go_remake/internal/mqtt/protocol/packet.go.
    """
    enc = Cipher(algorithms.AES(key), modes.CBC(CBC_IV)).encryptor()
    ct = enc.update(_pkcs7_pad(plaintext)) + enc.finalize()
    header_len = 64
    total = header_len + len(ct) + 1
    if total <= 0xFFFF:
        magic = b"MA"
        size_field = struct.pack("<H", total)
    else:
        magic = b"MB"
        size_field = struct.pack("<I", total + 2)  # +2 for the wider size field

    device_guid = str(uuid.uuid4()).encode("ascii").ljust(37, b"\x00")[:37]

    head = (
        magic
        + size_field
        + bytes(
            [
                0x05,  # M3
                0x01,  # M4
                0x02,  # M5 = 2 (app-to-printer flavour)
                0x05,  # M6
                0x46,  # M7 ('F')
                0xC0,  # packet_type = single
            ]
        )
        + struct.pack("<H", 0)  # packet_num
        + struct.pack("<I", 0)  # time (the desktop app sends 0)
        + device_guid
        + b"\x00" * 11  # padding
    )
    frame = head + ct
    return frame + bytes([_xor(frame)])


# --------------------------------------------------------------------------
# TLS and topic templates
# --------------------------------------------------------------------------


def make_tls_context(ca_file: str | None, insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    for path in filter(
        None,
        [ca_file, os.environ.get("EUFY_CA_FILE"), *APP_CERT_CANDIDATES],
    ):
        if os.path.exists(path):
            return ssl.create_default_context(cafile=path)
    log.warning(
        "no bundled CA found; the broker will probably reject the TLS handshake"
    )
    return ssl.create_default_context()


def subscribe_topics(sn: str, uid: str) -> list[str]:
    # The broker's ACL accepts these specific topics but refuses '#'/'+'
    # wildcards, so we have to enumerate them.
    return [
        f"/phone/maker/{sn}/notice",
        f"/phone/maker/{sn}/command/reply",
        f"/phone/maker/{sn}/query/reply",
        f"/phone/maker/{sn}/change_notice",
        f"/phone/user/{uid}/change_notice",
    ]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _pct(raw) -> float | None:
    """Interpret a leftInk value. The printer reports these as integer
    1/100ths of a percent, e.g. 7820 = 78.20%."""
    if raw is None:
        return None
    try:
        n = float(raw)
    except (TypeError, ValueError):
        return None
    if n > 100:
        return n / 100.0
    return n


def render_ink_block(
    payload: dict, sn: str, station_name: str = "eufyMake UV Printer E1"
) -> str | None:
    """Format a commandType-1100 dict as a human-readable block.

    The payload looks like::

        {
          "commandType": 1100,
          "ink": {"count": 6, "colorSort": [...], "leftInk": [...],
                  "sn": [...], "distanceExpiration": [...], ...},
          "wasteInk": {"count": 1, "leftInk": [<0-10000>],
                       "distanceExpiration": <days>, ...}
        }

    `leftInk` inside `ink` is "% remaining" in 1/100ths of a percent.
    `leftInk` inside `wasteInk` is "% full" in the same units (per
    charliex2's write-up).
    """
    ink_block = payload.get("ink")
    waste_block = payload.get("wasteInk")
    if not isinstance(ink_block, dict):
        return None
    left = ink_block.get("leftInk")
    if not isinstance(left, list) or len(left) < len(INK_CHANNELS):
        return None

    serials = ink_block.get("sn") if isinstance(ink_block.get("sn"), list) else None
    exp_days = ink_block.get("distanceExpiration")

    lines = [f"{station_name}  SN={sn}  (t={time.strftime('%H:%M:%S')})"]
    for i, (code, name) in enumerate(INK_CHANNELS):
        pct = _pct(left[i])
        bits = [f"  {code}  {name:<8}"]
        bits.append(f"{pct:6.2f} %" if pct is not None else "    —  ")
        if serials and i < len(serials) and serials[i]:
            bits.append(f"  sn={serials[i]}")
        if isinstance(exp_days, list) and i < len(exp_days):
            bits.append(f"  exp_in={exp_days[i]}d")
        lines.append("".join(bits))

    if isinstance(waste_block, dict):
        w_left = waste_block.get("leftInk")
        w_val = None
        if isinstance(w_left, list) and w_left:
            w_val = _pct(w_left[0])
        elif isinstance(w_left, (int, float)):
            w_val = _pct(w_left)
        w_exp = waste_block.get("distanceExpiration")
        w_bits = ["  Waste tank"]
        if w_val is not None:
            # `leftInk` in the wasteInk block is "% full", not "% remaining"
            # (the tank fills up over time as spent ink collects).
            w_bits.append(f"          {w_val:6.2f} % full")
        else:
            w_bits.append("             —")
        if isinstance(w_exp, int) and w_exp:
            w_bits.append(f"  exp_in={w_exp}d")
        lines.append("".join(w_bits))

    return "\n".join(lines)


# --------------------------------------------------------------------------
# MQTT client
# --------------------------------------------------------------------------


class Client:
    def __init__(
        self,
        cfg: Cfg,
        *,
        ca_file: str | None = None,
        insecure: bool = False,
        dump_dir: str | None = None,
        raw: bool = False,
    ):
        self.cfg = cfg
        self.dump_dir = dump_dir
        self.raw = raw
        self.got_ink = threading.Event()
        self.latest_ink: dict | None = None
        self._counter = 0  # for dump filenames

        if dump_dir:
            os.makedirs(dump_dir, exist_ok=True)

        client_id = (
            f"pc_macos_AnkerMakeStudio_direct_{cfg.user_id}_"
            f"{os.urandom(6).hex()}_{int(time.time() * 1000)}"
        )
        c = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
        )
        c.username_pw_set(f"eufy_{cfg.user_id}", cfg.email)
        c.tls_set_context(make_tls_context(ca_file, insecure))
        c.on_connect = self._on_connect
        c.on_subscribe = self._on_subscribe
        c.on_message = self._on_message
        self._client = c
        self._client_id = client_id
        self._connected = threading.Event()

    def connect(self, broker: str | None = None) -> None:
        b = broker or BROKERS.get(self.cfg.ab_code, DEFAULT_BROKER)
        log.debug("connecting mqtts://%s:%d", b, BROKER_PORT)
        self._client.connect(b, BROKER_PORT, keepalive=60)
        self._client.loop_start()
        if not self._connected.wait(timeout=15):
            raise SystemExit("MQTT connect timed out")

    def disconnect(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()

    def trigger_state_dump(self) -> None:
        """Ask the printer to broadcast its full state, including ink.

        Sends ``{"commandType": 1027, "value": 0}`` (AppQueryStatus) to
        ``/device/maker/<sn>/query`` wrapped in the 64-byte "M5" header
        variant. The printer acks on ``.../command/reply`` and then
        broadcasts a batched notice on ``.../notice`` that contains a
        ``commandType: 1100`` item with the live ink state.
        """
        body = json.dumps(
            {"commandType": CMD_APP_QUERY_STATUS, "value": 0},
            separators=(",", ":"),
        ).encode()
        frame = build_app_frame(self.cfg.secret_key, body)
        topic = f"/device/maker/{self.cfg.station_sn}/query"
        self._client.publish(topic, frame, qos=0)
        log.debug(
            "published ct=%d -> %s (%d bytes)", CMD_APP_QUERY_STATUS, topic, len(frame)
        )

    # -- paho-mqtt callbacks ------------------------------------------------

    def _on_connect(self, c, _userdata, _flags, rc, _props=None):
        if rc != 0:
            log.error("CONNACK rc=%s", rc)
            raise SystemExit(f"MQTT auth failed: {rc}")
        topics = subscribe_topics(self.cfg.station_sn, self.cfg.user_id)
        c.subscribe([(t, 0) for t in topics])
        log.debug("subscribed: %s", topics)
        self._connected.set()

    def _on_subscribe(self, _c, _userdata, _mid, reason_code_list, _props=None):
        refused = [
            (i, rc)
            for i, rc in enumerate(reason_code_list)
            if rc.getName() != "Granted QoS 0"
        ]
        if refused:
            log.warning("subscription refused: %s", refused)

    def _on_message(self, _c, _userdata, msg):
        self._counter += 1
        if self.dump_dir:
            safe = msg.topic.replace("/", "_").lstrip("_")
            path = os.path.join(
                self.dump_dir,
                f"{self._counter:04d}_{safe}_{len(msg.payload)}b.bin",
            )
            with open(path, "wb") as fh:
                fh.write(msg.payload)

        try:
            frame = parse_frame(msg.payload)
            pt = decrypt(self.cfg.secret_key, frame.ciphertext)
            payload = json.loads(pt)
        except Exception as e:  # parse / decrypt / json
            log.warning("dropping frame on %s: %s", msg.topic, e)
            return

        # Batched notices come as a JSON list of per-commandType dicts;
        # singleton replies come as a bare dict. Normalise to a list.
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            ct = item.get("commandType")
            if self.raw:
                print(
                    f"\n=== {msg.topic}  ct={ct}  "
                    f"m5={frame.m5}  xor={'ok' if frame.checksum_ok else 'BAD'} ==="
                )
                print(json.dumps(item, indent=2, ensure_ascii=False), flush=True)
            if ct == CMD_INK_STATUS:
                self.latest_ink = item
                rendered = render_ink_block(item, self.cfg.station_sn)
                if rendered:
                    print(rendered, flush=True)
                    self.got_ink.set()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _decode_from_file(path: str, cfg: Cfg, raw: bool) -> int:
    wire = Path(path).read_bytes()
    frame = parse_frame(wire)
    plaintext = decrypt(cfg.secret_key, frame.ciphertext)
    payload = json.loads(plaintext)
    items = payload if isinstance(payload, list) else [payload]
    found = False
    for item in items:
        if not isinstance(item, dict):
            continue
        if raw:
            print(json.dumps(item, indent=2, ensure_ascii=False))
        if item.get("commandType") == CMD_INK_STATUS:
            rendered = render_ink_block(item, cfg.station_sn)
            if rendered:
                print(rendered)
                found = True
    if not found:
        log.error("no commandType-1100 dict found in %s", path)
        return 3
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Print live ink levels for an eufyMake UV Printer E1"
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="stay connected and print every ink-status update",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="re-query every N seconds in --watch mode (default: 30)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        metavar="SECONDS",
        help="seconds to wait for the first reply in one-shot mode (default: 20)",
    )
    p.add_argument(
        "--raw",
        action="store_true",
        help="dump every decrypted MQTT item as JSON",
    )
    p.add_argument(
        "--dump",
        metavar="DIR",
        help="save every raw encrypted frame into DIR for offline replay",
    )
    p.add_argument(
        "--from-file",
        metavar="PATH",
        help="decode a previously-captured raw frame instead of connecting",
    )
    p.add_argument(
        "--device-index",
        type=int,
        default=0,
        help="pick a device when more than one is registered (default: 0)",
    )
    p.add_argument("--broker", help="override the MQTT broker host")
    p.add_argument("--ca-file", help="CA cert for the broker")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg = load_cfg(args.device_index)
    log.debug("station=%s user=%s region=%s", cfg.station_sn, cfg.user_id, cfg.ab_code)

    if args.from_file:
        return _decode_from_file(args.from_file, cfg, args.raw)

    client = Client(
        cfg,
        ca_file=args.ca_file,
        insecure=args.insecure,
        dump_dir=args.dump,
        raw=args.raw,
    )
    client.connect(args.broker)

    try:
        # Give paho a moment to finish subscribing before we publish.
        time.sleep(0.3)
        client.trigger_state_dump()

        if args.watch:
            log.info("watching; ^C to stop")
            while True:
                time.sleep(max(1.0, args.interval))
                client.trigger_state_dump()
        else:
            if not client.got_ink.wait(timeout=args.timeout):
                log.error(
                    "no commandType-1100 message received within %.0fs; is the "
                    "printer powered on?",
                    args.timeout,
                )
                return 2
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
