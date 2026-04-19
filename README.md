# eufy-ink

Print the real ink levels from an eufyMake UV Printer E1 on the command line, as
numbers, because the desktop app only shows a gradient bar that's nearly
impossible to read for the White and Gloss channels.

```
eufyMake UV Printer E1  SN=AK7226XXXXXXXXXXX  (t=17:32:27)
  C  cyan     78.20 %  sn=AR4800XXXXXXXXXXX  exp_in=164d
  M  magenta  77.30 %  sn=AR4801XXXXXXXXXXX  exp_in=164d
  Y  yellow   78.69 %  sn=AR4802XXXXXXXXXXX  exp_in=164d
  K  black    76.39 %  sn=AR4803XXXXXXXXXXX  exp_in=164d
  W  white    62.61 %  sn=AR4804XXXXXXXXXXX  exp_in=283d
  G  gloss    71.33 %  sn=AR4805XXXXXXXXXXX  exp_in=280d
  Waste tank           20.00 % full  exp_in=402d
```

These are the same numbers that drive the bars in the app's Ink Management panel
(to the hundredth of a percent), pulled straight off Anker's MQTT broker, live.

## How it works

The desktop app connects to `mqtts://make-mqtt.ankermake.com:8789`, subscribes
to a few per-device topics, and receives AES-256-CBC-encrypted status messages
from the printer. The per-cartridge fill level lives in the `commandType: 1100`
notice, whose payload looks like:

```json
{
  "commandType": 1100,
  "ink": {
    "count": 6,
    "colorSort":  ["C","M","Y","K","W","G"],
    "leftInk":    [7820, 7730, 7869, 7639, 6261, 7133],
    "sn":         ["AR4800XXXXXXXXXXX", ...],
    "status":     [1, 1, 1, 1, 1, 1],
    "expirationTimestamp":  [1790697600, ...],
    "distanceExpiration":   [164, 164, 164, 164, 283, 280],
    "expired":    [0, 0, 0, 0, 0, 0]
  },
  "wasteInk": { ... }
}
```

`leftInk` is in 1/100ths of a percent, so `7820 = 78.20 %`. This tool divides by
100 for display and prints it alongside the cartridge serial and the expiry
countdown.

### Auth

All credentials come from the desktop app's on-disk cache, so nothing has to be
re-entered:

- `station_sn`, `secret_key` →
  `~/Library/Application Support/eufyMake Studio Profile/cache/offline/device_info/device_list.json`
- `user_id`, `email`, region (`ab_code`) →
  `~/Library/Application Support/eufyMake Studio Profile/cache/offline/user_info/login_info.json`
- Broker CA → `/Applications/eufyMake Studio.app/Contents/MacOS/make-us.crt`

MQTT CONNECT:

```
username   eufy_<user_id>
password   <email (URL-decoded)>
client id  pc_macos_AnkerMakeStudio_direct_<user_id>_<12 hex>_<ms_since_epoch>
```

Subscribe topics (one slot per device):

```
/phone/maker/<station_sn>/notice
/phone/maker/<station_sn>/command/reply
/phone/maker/<station_sn>/query/reply
/phone/maker/<station_sn>/change_notice
/phone/user/<user_id>/change_notice
```

Publish topics:

```
/device/maker/<station_sn>/command
/device/maker/<station_sn>/query
```

The broker's ACL refuses `#` / `+` wildcard subscriptions; each topic has to be
listed out.

### Wire format

Every MQTT payload is an AES-256-CBC-encrypted JSON blob wrapped in a
fixed-layout binary header and followed by a single-byte XOR checksum. The
header comes in two flavours — one the printer sends to us, a different one we
must send to the printer:

```
[0:2]  magic  = b'MA' (size <= 0xFFFF) or b'MB' (4-byte size field)
[2:4]  total_size      uint16 LE   (or uint32 LE at [2:6] for 'MB')
[4]    M3 = 0x05
[5]    M4 = 0x01
[6]    M5 = 0x06 when printer->app (24-byte header, no DeviceGUID)
              0x02 when app->printer (64-byte header, with DeviceGUID)
[7]    M6 = 0x05
[8]    M7 = 0x46 = 'F'
[9]    packet_type: 0xC0 = single-packet, 0xC1..0xC3 = fragmented
[10:12] packet_num      uint16 LE  (printer sends incrementing; app sends 0)
            --- M5=2 (64-byte header) only: ---
[12:16] time            uint32 LE  (usually 0 from the app)
[16:53] device_guid     37-byte C-string (a random UUID from the app)
[53:64] 11 zero bytes
            --- M5=6 (24-byte header) only: ---
[12:24] 12 zero bytes (or sometimes a timestamp + small ints; unused)
            --- common: ---
[hdr:-1] ciphertext      AES-256-CBC, PKCS7 padded, multiple of 16
[-1]     xor_checksum    single byte, XOR of everything preceding it
```

Key = the 32-byte `secret_key` from `device_list.json` (stored there as 64 hex
chars). IV = the fixed 16-byte ASCII string `b"3DPrintAnkerMake"`.

This format is confirmed by the symbols and log-message strings baked into
`libAnkerNet.dylib` (`CbcEncrypt`, `CbcDecrypt`,
`"XOR checksum verification failed! Protocol:"`,
`"Mqtt Aes Cbc Decrypt Error!"`, etc.) and by cross-referencing Django1982's
`ankerctl_go_remake` Go client, which uses the same scheme for the AnkerMake M5
3D printer. The UV printer just tags its broadcast frames with a different `M5`
byte (`6` rather than `2`), hence the 24-byte header with no DeviceGUID.

Status notices on `/phone/maker/<sn>/notice` are often **batched** as a JSON
_list_ of per-`commandType` dicts; singleton replies on `.../command/reply` and
`.../query/reply` come as a bare dict. The tool handles both shapes.

### Triggering a fresh ink-status push

We send `{"commandType": 1027, "value": 0}` to `/device/maker/<sn>/query` as
soon as we connect. 1027 is `MqttCmdAppQueryStatus` (0x0403) — the same "phone
just connected, please send everything" command the AnkerMake M5 Go client uses.
The printer responds with an ack on `.../command/reply` and then publishes a big
batched notice on `.../notice` that includes the current ink state as a
`commandType: 1100` item.

Important: the printer _only_ accepts our command frame when it's wrapped in the
64-byte "M5" variant of the header (i.e. `M5 byte = 2`, with a random UUID in
the DeviceGUID slot). A 24-byte frame (the variant the printer itself emits) is
silently dropped with no ack. Both variants use the same AES key and IV.

## Usage

```
# one shot, waits up to 20 s for a 1100 message
python3 eufy_ink.py

# stay connected and print every update
python3 eufy_ink.py --watch

# dump every decrypted MQTT message as JSON (great for discovery)
python3 eufy_ink.py --watch --raw

# save every raw encrypted frame to a directory for later replay
python3 eufy_ink.py --watch --dump /tmp/eufy-capture

# re-decode a previously captured frame without touching the network
python3 eufy_ink.py --from-file /tmp/eufy-capture/0005_...notice_2857b.bin
```

Dependencies:

```
pip install -r requirements.txt   # paho-mqtt, cryptography
```

If you have more than one printer registered under the same account pass
`--device-index N`. Set `EUFY_PROFILE_DIR` to override the profile directory.
Set `EUFY_CA_FILE` (or pass `--ca-file`) to point at a different CA bundle if
Anker rotates the cert. `--insecure` skips TLS verification entirely.

### `--watch` mode

In `--watch` the tool re-fires the 1027 status query every `--interval` seconds
(default 30s) so the printout tracks the printer's current state.

## Docker and Grafana Cloud (optional)

For persistent monitoring and long-term trend analysis, this tool can run in a
Docker container and push metrics to Grafana Cloud using the Prometheus Agent
via remote write.

### Architecture

```
┌──────────────────────┐
│  eufy-ink container  │  :8080
│  (MQTT → metrics)    │──────────────┐
└──────────────────────┘              │ scrape
                                     ▼
┌──────────────────────┐       ┌──────────────┐
│  Prometheus Agent    │◄───────│   Grafana    │
│  (WAL on disk)       │ push  │   Cloud      │
│                      │──────►│              │
└──────────────────────┘       └──────────────┘
```

The Prometheus Agent runs in "Agent mode" (`--enable-feature=agent`), which is
specifically designed for this edge-to-cloud pattern. It uses a Write-Ahead Log
(WAL) stored in the `prometheus_data` Docker volume, so metrics are buffered
locally and forwarded to Grafana Cloud when connectivity is available. This
prevents data gaps during internet outages or container restarts.

### Setup

1. **Clone and configure credentials**

   Run the helper script to extract credentials from the profile cache:

   ```bash
   # Run on the machine with the desktop app installed
   python3 scripts/export-env.py > .env
   # Review the output, then copy .env to your container host
   ```

   Or manually create a `.env` file (keep this file private):

   ```bash
   cat > .env << 'EOF'
   EUFY_USER_ID=your_user_id_here
   EUFY_EMAIL=your.email@example.com
   EUFY_REGION=US
   EUFY_STATION_SN=AK7226XXXXXXXXXXX
   EUFY_SECRET_KEY=your_64_char_hex_key_here
   EOF
   ```

2. **Configure Grafana Cloud remote write**

   Open `prometheus.yml` and replace the placeholders:
   - `<INSTANCE_ID>` — your Grafana Cloud instance ID (found in the portal URL,
     e.g., `grafana.com/orgs/myorg` → instance ID is in the metrics URL)
   - `<PROMETHEUS_USER>` — your Grafana Cloud Prometheus user (e.g., `1234567`)
   - `<PROMETHEUS_PASSWORD>` — your Grafana Cloud API Key with the
     `MetricsPublisher` role (create one in your Grafana Cloud account under
     **Security → API Keys**)

3. **Launch**

   ```bash
   docker compose up -d
   ```

   This starts two containers:
   - `eufy-ink` — queries the printer and exposes metrics on port 8080
   - `prometheus` — scrapes the metrics and pushes them to Grafana Cloud

4. **Verify**

   Check the logs:

   ```bash
   docker compose logs -f
   ```

   Visit `http://localhost:9090` to see Prometheus scraping the metrics locally.
   In Grafana Cloud, go to **Explore → Metrics** and search for `eufy_ink`.

### Prometheus Metrics

The following metrics are exposed when `--metrics-port` is provided:

| Metric                         | Type  | Description                             | Labels          |
| ------------------------------ | ----- | --------------------------------------- | --------------- |
| `eufy_ink_level_percent`       | Gauge | Ink remaining per channel (%)           | channel, serial |
| `eufy_ink_expiry_days`         | Gauge | Days until cartridge expires            | channel, serial |
| `eufy_waste_tank_full_percent` | Gauge | Waste tank fill level (%)               | —               |
| `eufy_waste_tank_expiry_days`  | Gauge | Days until waste tank needs replacement | —               |

### Running without the profile cache

Instead of mounting the desktop app's profile directory, you can pass
credentials directly as environment variables (`EUFY_USER_ID`, `EUFY_EMAIL`,
`EUFY_REGION`, `EUFY_STATION_SN`, `EUFY_SECRET_KEY`). This is the recommended
approach for running on a separate host machine.

## Caveats

- These are cloud-round-tripped numbers. The desktop app also talks to the
  printer over a P2P channel (UDP hole punch) when you're on the same network,
  and the two feeds should agree. This tool only uses the MQTT/cloud path.
- The `secret_key` and email live in plaintext in the app's profile dir. If you
  uninstall the app, you'll need to sign in once more before this tool works.
- The ACL on Anker's broker seems to allow multiple subscribers per user (the
  desktop app, this tool, and your phone can all be connected at the same time).

## Credits / references

- Charlie Xenophon's initial write-up of the protocol:
  https://charliex2.wordpress.com/2026/03/06/eufy/
- Django1982's `ankerctl_go_remake` protocol notes (AnkerMake M5/M5C 3D printer,
  closely related topic/framing scheme):
  https://github.com/Django1982/ankerctl_go_remake/blob/main/docs/wiki/Protocol-Details.md

The exact UV-printer quirks (CBC rather than GCM, the `"MA"`/`"MB"` two-flavour
header, the batched-list vs singleton-dict notice convention, the
`/phone/maker/<sn>/change_notice` subscription, the wildcard ACL refusal) were
worked out from captures and from strings in the app's `libAnkerNet.dylib`.
