#!/usr/bin/env python3
"""Xenfire Tools - device backend (USB only, via libimobiledevice)"""
import subprocess

def _run(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return False, "", f"Command not found: {cmd[0]}. Did you run install.sh?"
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out."

def device_connected():
    ok, out, _ = _run(["idevice_id", "-l"])
    return ok and len(out.strip()) > 0

def get_device_info():
    if not device_connected():
        return None
    info = {}
    fields = {
        "DeviceName": "Name",
        "ProductType": "Model",
        "ProductVersion": "iOS Version",
        "SerialNumber": "Serial",
        "UniqueDeviceID": "UDID",
    }
    for key, label in fields.items():
        ok, out, _ = _run(["ideviceinfo", "-k", key])
        info[label] = out if ok else "Unknown"
    return info

def install_ipa(path, progress_callback=None):
    if not device_connected():
        return False, "No device connected. Plug in via USB and trust this computer."

    proc = subprocess.Popen(
        ["ideviceinstaller", "-i", path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    output_lines = []
    for line in proc.stdout:
        output_lines.append(line.strip())
        if progress_callback:
            progress_callback(line.strip())
    proc.wait()

    full_output = "\n".join(output_lines)
    if proc.returncode == 0:
        return True, full_output
    return False, full_output
