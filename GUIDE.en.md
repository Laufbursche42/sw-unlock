# Guide

> **Feasibility study.** This page shows what Segway-Ninebot's Bluetooth protocol makes accessible today. It is not a finished product. Error-free operation is not promised and there is no warranty. Whatever you do with it, you do at your own risk and on your own vehicle only.

> **Important for error reports:** switch on the **Diagnostic log** at the bottom of the page *before* you connect to the scooter. Only then is the full connection handshake captured - and those are exactly the lines we need in a [ticket](https://github.com/Laufbursche42/Laufbursche42/issues) to reproduce a problem.

> **Already paired with the Segway account?** Then the scooter often will not hand out a fresh pairing
> password on a button press and the handshake stalls. A scooter that has never been paired with the app
> is the easiest to connect.

## What you need

- A Segway-Ninebot scooter from the official app `com.ninebot.segway`, one of 17 supported families
  (E-series, GT, Max, F, ES, P, C2 Pro, E2 and more).
- A browser with Web Bluetooth: **Chrome** or **Edge** on Android or desktop, **Bluefy** on the iPhone.
  Safari has no Web Bluetooth.
- The scooter on and in range.

## 1. Open the page

Open the page in a supported browser ([laufbursche42.github.io/sw-unlock](https://laufbursche42.github.io/sw-unlock/)).
At the top you see the header with the connection status, the light/dark switch and the language toggle
DE/EN.

## 2. Pick your model

The **model picker** lists 17 scooter families. Picking your model sets the right board, registers and
frame generation for that family **automatically** and hides levers the model does not have. Choose your
model before you connect so the right registers are in place.

## 3. Connect

Tap **Connect** and pick your scooter in the Bluetooth chooser. The page auto-detects the Ninebot
Nordic-UART service and its write/notify characteristics. On first connect, allow all services and
characteristics. Some scooters only answer once they are awake - **if the connection does not come up,
press the power button on the scooter** so it accepts the link. After connecting the status reads
**connected**, and the Encryption2 handshake runs automatically.

## 4. Read the live values

The page reads what the scooter reports: serial number, firmware version, current speed, battery level,
riding mode and the BMS values the family exposes. Values without a confirmed basis are marked `[?]`.
**Read all values** re-reads without reconnecting. Reading changes nothing on the scooter.

## 5. Read and sanity-check before you write

Only the E-series speed register is byte-verified; every other register is community-sourced and flagged
`[?]`. Read the current value first, check it is plausible for your scooter, and only then write. An echo
in the log means the frame was **accepted**; only the setting re-appearing in the live values with the new
number proves it actually **took effect**. Every write asks for confirmation first.

## 6. Set or release the speed limit

The speed-limit control writes the maximum speed in km/h to the controller's speed register for your
family. A single **lock / unlock** toggle locks it down to the legal cap or opens it, where the family
exposes it. Riding mode (Eco / Drive / Sport), KERS (Off / Medium / Strong), cruise control and the tail
light are set the same way, where supported.

## 7. Back up the serial / region first

Before you write anything, read the **serial number and region** and **save the backup** - a JSON download
that is also kept in local storage. On the families that support it you can rewrite the serial over BLE,
behind a risk checkbox and a double confirmation, or restore it from the backup. Make the backup first so
you can always put the original values back.

## 8. Expert raw console

For experts, the **raw register console** reads any register (decode as u8 / u16le / u16be / u32le / ascii)
and writes any register behind a confirmation, with ready-made presets for every speed lever of both
protocol families. Commands that need a token the tool does not have (the 16-byte identity token for
"open ACC" / immobiliser) are deliberately **not** wired up.

## 9. Share the log

The **Log** shows every sent and received frame as hex with a timestamp, plus the decoded values. By
default it is **anonymized** - addresses, serial numbers and device IDs are redacted - so you can share it
safely. **Copy log** or **Save as .txt** hands the capture over, which helps understand the protocol on
real hardware.

## If something does not work

- **The scooter does not appear in the list.** Is it on and in range? Wake it with the power button.
- **No notify arrives.** Check the log for RX lines. Some models only answer after a short warm-up, or
  after you press the power button.
- **A value stays `[?]` or empty.** Then the family does not report that value over Bluetooth, or it is
  community-sourced and untested. Send the log so the flow can be traced.

## Legal

Changing the speed limit removes the manufacturer's limiter and ends the road approval; use on public roads
is then not allowed and in many countries a criminal offence. Use the tool only on your own vehicle on
private, closed-off ground and at your own risk. See the [Disclaimer](DISCLAIMER.md).

## Contribute

Want to find out if and how a register works on your scooter? Test this tool on your own vehicle and open a
[ticket](https://github.com/Laufbursche42/Laufbursche42/issues) - with your model and what worked
(or did not), and the anonymized log. That way we verify together what each family really accepts.
