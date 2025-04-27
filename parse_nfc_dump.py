#!/usr/bin/env python3
import sys
import os
import re
import struct
import argparse
import json
from datetime import datetime


# Helper functions for little-endian decoding
def le_uint16(bytes_):
    return bytes_[0] | (bytes_[1] << 8)


def le_float(bytes_):
    return struct.unpack("<f", bytes(bytes_))[0]


# Print a colored swatch in terminal using ANSI 24-bit background
def print_color_swatch(r, g, b):
    sys.stdout.write(f"\x1b[48;2;{r};{g};{b}m  \x1b[0m\n")


def print_parsed(blocks, header, colors_map, filepath):
    print(f"Parsed {filepath}\n")

    # Header fields
    if header:
        for key in ("UID", "ATQA", "SAK", "Mifare Classic type"):
            if key in header:
                print(f"{key}: {header[key]}")
        print()

    # Block 0 - UID & Manufacturer data
    b0 = blocks.get(0)
    if b0:
        uid = "".join(f"{b0[i]:02X}" for i in range(4))
        manuf = "".join(f"{b0[i]:02X}" for i in range(4, 16))
        print(f"Block 0 - UID: {uid}")
        print(f"Block 0 - Manufacturer Data: {manuf}\n")

    # Block 1 - Tray Info Index
    b1 = blocks.get(1)
    if b1:
        t1 = bytes(b1[0:8]).rstrip(b"\x00").decode("ascii", errors="ignore")
        t2 = bytes(b1[8:16]).rstrip(b"\x00").decode("ascii", errors="ignore")
        print(f"Block 1 - Tray Info Index: {t1} | {t2}\n")

    # Block 2 - Filament Type
    b2 = blocks.get(2)
    if b2:
        ft = bytes(b2).rstrip(b"\x00").decode("ascii", errors="ignore")
        print(f"Block 2 - Filament Type: {ft}\n")

    # Block 4 - Detailed Filament Type
    b4 = blocks.get(4)
    filament_type = None
    if b4:
        dt = bytes(b4).rstrip(b"\x00").decode("ascii", errors="ignore")
        filament_type = dt
        print(f"Block 4 - Detailed Filament Type: {dt}\n")

    # Block 5 - RGBA, Spool Weight, Filament Diameter + Color lookup
    b5 = blocks.get(5)
    if b5:
        r, g, b, a = (b5[i] or 0 for i in range(4))
        rgba_hex = "".join(f"{v:02X}" for v in (r, g, b, a))
        rgb_hex = rgba_hex[:6]
        weight = le_uint16(b5[4:6])
        diameter = le_float(b5[8:12])
        print(f"Block 5 - Color RGBA: {rgba_hex}")
        # Lookup name and code using RGB only
        if filament_type and filament_type in colors_map:
            info = colors_map[filament_type].get(rgb_hex)
            if info:
                print(f"Block 5 - Color Name: {info['name']}")
                print(f"Block 5 - Color Code: {info['code']}")
        print("Block 5 - Color Swatch:", end=" ")
        print_color_swatch(r, g, b)
        print(f"Block 5 - Spool Weight: {weight} g")
        print(f"Block 5 - Filament Diameter: {diameter:.2f} mm\n")

    # Block 6 - Drying & Temperature
    b6 = blocks.get(6)
    if b6:
        dtg = le_uint16(b6[0:2])
        dth = le_uint16(b6[2:4])
        btt = le_uint16(b6[4:6])
        btemp = le_uint16(b6[6:8])
        hot_max = le_uint16(b6[8:10])
        hot_min = le_uint16(b6[10:12])
        print(f"Block 6 - Drying Temperature: {dtg} °C")
        print(f"Block 6 - Drying Time: {dth} h")
        print(f"Block 6 - Bed Temp Type: {btt}")
        print(f"Block 6 - Bed Temperature: {btemp} °C")
        print(f"Block 6 - Hotend Max: {hot_max} °C")
        print(f"Block 6 - Hotend Min: {hot_min} °C\n")

    # Block 8 - X-Cam & Nozzle
    b8 = blocks.get(8)
    if b8:
        cam = "".join(f"{b:02X}" for b in b8[0:12])
        noz = le_float(b8[12:16])
        print(f"Block 8 - X-Cam Info: {cam}")
        print(f"Block 8 - Minimal Compatible Nozzle Diameter: {noz:.2f} mm\n")

    # Block 9 - Tray UID
    b9 = blocks.get(9)
    if b9:
        tu = " ".join(f"{byte:02X}" for byte in b9 if byte is not None)
        print(f"Block 9 - Tray UID: {tu}\n")

    # Block 10 - Spool Width
    b10 = blocks.get(10)
    if b10:
        sw = le_uint16(b10[4:6])
        print(f"Block 10 - Spool Width: {sw/100:.2f} mm\n")

    # Block 12 - Production DateTime (raw + parsed)
    b12 = blocks.get(12)
    if b12:
        raw_pd = bytes(b12).decode("ascii", errors="ignore").rstrip("\x00")
        print(f"Block 12 - Production DateTime (raw): {raw_pd}")
        try:
            dt = datetime.strptime(raw_pd, "%Y_%m_%d_%H_%M")
            print(
                f"Block 12 - Production DateTime (parsed): {dt.strftime('%B %d, %Y %H:%M')}"
            )
        except ValueError:
            pass
        print()

    # Block 13 - Short Production Date (raw + parsed)
    b13 = blocks.get(13)
    if b13:
        raw_sp = bytes(b13).decode("ascii", errors="ignore").rstrip("\x00")
        print(f"Block 13 - Short Production Date (raw): {raw_sp}")
        # Attempt multiple parse formats
        try:
            if "_" in raw_sp:
                parts = raw_sp.split("_")
                if len(parts) == 3:
                    dt2 = datetime.strptime(raw_sp, "%y_%m_%d")
                    print(
                        f"Block 13 - Short Production Date (parsed): {dt2.strftime('%B %d, %Y')}"
                    )
                elif len(parts) == 4:
                    dt2 = datetime.strptime(raw_sp, "%y_%m_%d_%H")
                    print(
                        f"Block 13 - Short Production DateTime (parsed): {dt2.strftime('%B %d, %Y %H:00')}"
                    )
            else:
                dt2 = datetime.strptime(raw_sp, "%Y%m%d")
                print(
                    f"Block 13 - Short Production Date (parsed): {dt2.strftime('%B %d, %Y')}"
                )
        except ValueError:
            pass
        print()

    # Block 14 - Filament Length
    b14 = blocks.get(14)
    if b14:
        fl = le_uint16(b14[4:6]) / 1000
        print(f"Block 14 - Filament Length: {fl:.2f} m\n")

    # Block 16 - Extra Color Info + conditional swatch
    b16 = blocks.get(16)
    if b16:
        fmt_id = le_uint16(b16[0:2])
        color_count = le_uint16(b16[2:4])
        a2, b2, g2, r2 = (b16[i] or 0 for i in range(4, 8))
        rgba2_hex = "".join(f"{v:02X}" for v in (r2, g2, b2, a2))
        rgb2_hex = rgba2_hex[:6]
        print(f"Block 16 - Format ID: {fmt_id:04X}")
        print(f"Block 16 - Color Count: {color_count}")
        if color_count > 1:
            print(f"Block 16 - Second Color RGBA: {rgba2_hex}")
            if filament_type and filament_type in colors_map:
                info2 = colors_map[filament_type].get(rgb2_hex)
                if info2:
                    print(f"Block 16 - Second Color Name: {info2['name']}")
                    print(f"Block 16 - Second Color Code: {info2['code']}")
            print("Block 16 - Color Swatch:", end=" ")
            print_color_swatch(r2, g2, b2)
        print()


def parse_flipper_dump(filepath):
    header, blocks = {}, {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if ":" in line and not line.startswith("Block "):
                k, v = [s.strip() for s in line.split(":", 1)]
                header[k] = v
            if line.startswith("Block "):
                m = re.match(r"Block (\d+): (.+)", line)
                if m:
                    num = int(m.group(1))
                    blocks[num] = [
                        int(x, 16) if x != "??" else None for x in m.group(2).split()
                    ]
    return header, blocks


def parse_proxmark_dump(filepath):
    """
    Parse Proxmark dump in binary or JSON format.
    JSON format should include top-level 'Card' and 'blocks' keys.
    """
    # Try JSON first
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        # JSON format
        header = {}
        card = data.get("Card", {})
        if "UID" in card:
            header["UID"] = ":".join(
                card["UID"][i : i + 2] for i in range(0, len(card["UID"]), 2)
            )
        if "ATQA" in card:
            header["ATQA"] = card["ATQA"]
        if "SAK" in card:
            header["SAK"] = card["SAK"]
        blocks = {}
        for num_str, hexstr in data.get("blocks", {}).items():
            try:
                num = int(num_str)
                # convert hex string to byte list
                blocks[num] = [
                    int(hexstr[i : i + 2], 16) for i in range(0, len(hexstr), 2)
                ]
            except ValueError:
                continue
        return header, blocks
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Fallback to raw binary dump
        blocks = {}
        with open(filepath, "rb") as f:
            raw = f.read()
        for i in range(len(raw) // 16):
            blocks[i] = list(raw[i * 16 : (i + 1) * 16])
        return {}, blocks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse NFC dumps (Flipper or Proxmark)"
    )
    parser.add_argument("filepath", help="Path to dump file")
    parser.add_argument("--format", choices=["flipper", "proxmark"], help="dump format")
    parser.add_argument(
        "--colors-json",
        default="filament_colors.json",
        help="Path to filament colors JSON file",
    )
    args = parser.parse_args()

    if not os.path.exists(args.filepath):
        print(f"File not found: {args.filepath}")
        sys.exit(1)
    if not os.path.exists(args.colors_json):
        print(f"Colors JSON not found: {args.colors_json}")
        sys.exit(1)

    # Load color lookup map
    with open(args.colors_json, "r") as cj:
        colors_map = json.load(cj)

    fmt = args.format
    if not fmt:
        try:
            with open(args.filepath, "r") as f:
                first = f.readline()
            if "Flipper NFC device" in first:
                fmt = "flipper"
        except (OSError, UnicodeDecodeError):
            fmt = None
        if not fmt:
            ext = os.path.splitext(args.filepath)[1].lower()
            fmt = "proxmark" if ext in (".bin", ".json") else "flipper"

    if fmt == "proxmark":
        header, blocks = parse_proxmark_dump(args.filepath)
    else:
        header, blocks = parse_flipper_dump(args.filepath)

    print_parsed(blocks, header, colors_map, args.filepath)
