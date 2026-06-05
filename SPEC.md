# Wifi Portal

Software to run a separate SSID in my home, for guests and IOT/smart devices to use whilst keeping them separate from my personal devices.

Challenge the feature requests if they don't make complete sense. Be thorough and consider security.

## Hardware

Raspberry Pi 3

## Features

- Creates a separate SSID, piggy-backing on my personal SSID
- This separate SSID can be used my smart devices e.g. my TV without giving that device access to the rest of my network
- This separate SSID will also be used by house guests
  - Ideally guests will connect to the SSID without needing a password and be greeted with a captive portal (like in a cafe) into which they'll enter an easy-to-type password that rotates every month and which only I can view by visiting a web page and then sharing that password with them
  - Alternatively I can visit a webpage only I have access to which shows a QR code that they can scan to get access to the separate SSID
  - Consider the approaches and decide which approach is best
  - If the smart device requirement and guest requirement are incompative, consider alternatives e.g. possible to use a single Pi for two separate SSIDs?

## Technicals

- Keep things simple and boring, don't use exotic languages or technology
- Provide instructions in a README how to deploy this software onto a Pi (3)
