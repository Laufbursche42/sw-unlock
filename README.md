# Laufbursche SEGWAY-NINEBOT unlock

A static web page that talks to Segway-Ninebot electric scooters over Web Bluetooth. Connect, read the live values and - straight from the browser - set the speed limit, the riding mode, KERS and cruise control, toggle the speed-limit lock and read, back up or (where the model allows) rewrite the serial/region. Nothing to install: no app store, no signing, no developer account. It runs in **Bluefy** on iOS and in **Chrome** or **Edge** on Android or desktop.

> **Reading is safe; almost every write is unverified on hardware.** Only the E-series speed register (DIS board `0x01`, register `0x93`, whole km/h) is byte-verified against a device. Every other register comes from community references and is **not** tested on a vehicle - the page marks these `[?]`, and a frame the scooter echoes back only means it was accepted, not that the value took effect. Read and sanity-check before you write, and read the [Disclaimer](#disclaimer) before you connect a scooter.

**Open the web app: [laufbursche42.github.io/sw-unlock](https://laufbursche42.github.io/sw-unlock/)**

Or run it yourself, no build step and no dependencies: clone the repo and serve the folder over a local HTTP server. Opening `index.html` directly as a `file://` URL will not work, the page fetches its own documents and browsers block that over `file://`.

```
git clone https://github.com/Laufbursche42/sw-unlock.git
cd sw-unlock
python -m http.server 8000
```

Any static server works. With Node installed, this does the same job:

```
npx serve .
```

Then open the printed address in a browser that supports Web Bluetooth.

## What it does

- **Model picker** - 17 scooter families (E-series, GT, Max, F, ES, P, C2 Pro, E2 and more). Picking the model sets the board, registers and generation, hides levers the model does not have and shows a capability line (✓/✗) for speed limit, mode, KERS, cruise, tail light and SN/region.
- **Speed limit** - set the maximum speed in km/h, written to the controller's speed register for that family.
- **Speed-limit lock** - a single toggle: lock (throttle down to the legal cap) or unlock (open), where the family exposes it.
- **Riding mode** - switch between Eco, Drive and Sport.
- **KERS** - regenerative braking strength: Off, Medium or Strong.
- **Cruise control and tail light** - toggle on and off, where supported.
- **Read what the scooter reports** - serial number, firmware version, current speed, battery level, riding mode and the BMS values the family exposes.
- **Serial / region** - read the serial and region, back it up as a JSON download (and to local storage), and on the families that support it rewrite the serial over BLE (behind a risk checkbox and a double confirmation) or restore it from a backup.
- **Expert raw console** - read any register (decode as u8 / u16le / u16be / u32le / ascii) and write any register with confirmation, with ready-made presets for every speed lever of both protocol families.

## Protocol (proven)

- **Service auto-detect** - the Ninebot Nordic-UART service (`6e400001-0000-0000-006e-696e65626f74`) and its write/notify characteristics, with fallbacks for the Nordic, ISSC, HM-Soft (`0xFFE0`) and `0xFEE7` layouts plus a 16-bit vendor scan.
- **Frame** - `5A A5` (GEN2) / `5A B5` (GEN3) header, length, source `0x3E`, target board, command, register, then payload. RX is reassembled from notifications and the counter is taken from the frame.
- **Encryption2** - AES-128 CTR for the payload with a CBC-MAC authentication tag, keyed on the non-serial `PRE_COMM` path. The crypto is never guessed: a wrong key fails silently, so it must match the device exactly.

## Honesty

Device-untested by design - you test on your own scooter, which is exactly the point of a public tool. An echo in the log means the scooter **accepted** the frame; only the setting re-appearing in the live values with the new value proves it actually took effect. Except for the E-series speed register, every value is community-sourced and flagged as unverified. Commands that need a token the tool does not have (the 16-byte identity token for "open ACC" / immobiliser) are **gated, not guessed** - they are deliberately not wired up. There is no separate "V3" protocol to fear: a published GT3 Pro BLE reference and a community-confirmed Max G3 both use the same Encryption2 this tool speaks. The real limit on an already-paired modern scooter is the account lock (the app's pairing password), not the encryption.

## Disclaimer

**Please read this in full before you connect a scooter.**

- **This is a feasibility study**, not a finished product. It shows what Segway-Ninebot's Bluetooth protocol makes possible. Nothing here promises that it works with your scooter, your phone or your browser, or that it still works after the next controller firmware or browser release.
- **Almost every write is unconfirmed on hardware.** Only the E-series speed register (`0x93`) is byte-verified; every other register comes from community references, and a frame the scooter echoes back only means it was accepted, not that the value took effect.
- **Changing the speed limit ends the road approval.** A scooter that no longer holds its approved speed limit is not road-legal any more; the operating permit is void and the insurance cover goes with it.
- **Ride a derestricted scooter on private property only**, on closed grounds that are not public traffic space. Riding one in public traffic is a criminal offence in many countries.
- **No liability**, as far as the law allows, for any damage caused by or with this tool, and **no warranty** of function, correctness or fitness for a particular purpose. Everything you do with this page is **at your own risk**.

By using this page you accept these terms. The full text is in [DISCLAIMER.md](DISCLAIMER.md).

## License

PolyForm Noncommercial 1.0.0 with additional terms, in full in [LICENSE.md](LICENSE.md). The source is public so anyone can read exactly what this page does to a scooter before running it; it is not free for commercial use.

## Privacy

Nothing leaves your device but the page load itself. The page is static HTML, CSS and JavaScript: no server, no backend, no analytics, no tracking. The details are in [PRIVACY.md](PRIVACY.md).

## Trademarks

An independent project, not affiliated with Segway, Ninebot or Xiaomi. "Segway", "Ninebot" and other product names are trademarks of their respective owners and are used here only to say which scooters this page works with. See [TRADEMARKS.md](TRADEMARKS.md).

Source: https://github.com/Laufbursche42/sw-unlock
