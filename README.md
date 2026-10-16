# Xenfire Tools

A local desktop GUI for Linux that lets you install `.ipa` files onto an iPhone over USB, with a local account/login gate. Built with Python, Tkinter, and `libimobiledevice`.

> ⚠️ **Local-only accounts:** Accounts are stored locally on each user's own machine (`~/.xenfire_tools/accounts.json`). This is not a shared online service — there's no central server, and accounts don't sync between devices or users.

## Features

- 🔒 Login-gated — nothing is usable until you sign in or create an account
- 📝 Multi-section signup (account info, age verification, security question) — in-app or via QR code scan from your phone
- 📱 Install `.ipa` files to a connected iPhone over USB
- 🧩 Placeholder tabs for upcoming features (Passkeys, Email tools, More)

## Requirements

- Linux (tested on Chromebook Crostini / Debian)
- Python 3
- An iPhone + USB cable
- An `.ipa` file signed with your own Apple ID / developer certificate (this tool does not sign apps — it installs already-signed packages, the same way AltStore/SideStore do)

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/Xenfire-Tools.git
cd Xenfire-Tools
chmod +x install.sh xenfire_tools.py
./install.sh
```

## Usage

```bash
./xenfire_tools.py
```

1. Create an account (in-app form, or scan the QR code with your phone — **your phone must be on the same Wi-Fi network** as this computer)
2. Sign in
3. Connect your iPhone via USB and tap "Trust This Computer" on the phone
4. Go to the **Install IPA** tab, click **Refresh Device**, browse to your `.ipa`, and click **Install**

## Notes

- Bluetooth is not used anywhere — iPhone communication is over USB only, via `libimobiledevice`/`ideviceinstaller`.
- QR signup only works over your local Wi-Fi network; it is not reachable from the internet.
- Passwords and security answers are stored as salted PBKDF2 hashes, never in plaintext.

## License

[Pick one — MIT is common for small open tools]
