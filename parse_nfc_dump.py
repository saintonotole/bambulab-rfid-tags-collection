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


# Print a colored block in terminal using ANSI 24-bit background
def print_color_block(r, g, b):
    sys.stdout.write(f"\x1b[48;2;{r};{g};{b}m  \x1b[0m\n")


# Print gradient between two colors
def print_color_gradient(r1, g1, b1, r2, g2, b2, steps=10):
    for i in range(steps):
        ri = int(r1 + (r2 - r1) * i / (steps - 1))
        gi = int(g1 + (g2 - g1) * i / (steps - 1))
        bi = int(b1 + (b2 - b1) * i / (steps - 1))
        sys.stdout.write(f"\x1b[48;2;{ri};{gi};{bi}m  \x1b[0m")
    sys.stdout.write("\n")


# Parse and print all relevant blocks
def print_parsed(blocks, header, colors_map, filepath):
    print(f"Parsed {filepath}")
    if header:
        for key in ("UID", "ATQA", "SAK", "Mifare Classic type"):
            if key in header:
                print(f"{key}: {header[key]}")

    # Block 4: Detailed Filament Type
    filament_type = None
    b4 = blocks.get(4)
    if b4:
        filament_type = bytes(b4).rstrip(b"\x00").decode("ascii", errors="ignore")
        print(f"Block 4 - Detailed Filament Type: {filament_type}")

    # Block 16: Secondary color info
    rgb2 = None
    b16 = blocks.get(16)
    if b16:
        count = le_uint16(b16[2:4])
        if count > 1:
            a2, b2, g2, r2 = (b16[i] or 0 for i in range(4, 8))
            rgb2 = (r2, g2, b2)

    # Block 5: Primary color, weight, diameter
    r1 = g1 = b1 = a1 = None
    b5 = blocks.get(5)
    if b5:
        r1, g1, b1, a1 = (b5[i] or 0 for i in range(4))
        rgba_hex = f"{r1:02X}{g1:02X}{b1:02X}{a1:02X}"
        rgb_hex = rgba_hex[:6]
        weight = le_uint16(b5[4:6])
        diameter = le_float(b5[8:12])
        print(f"Block 5 - Color RGBA: {rgba_hex}")
        # Lookup color name and code
        color_info = None
        if filament_type in colors_map:
            if rgb2:
                combo = f"{rgb_hex};{rgb2[0]:02X}{rgb2[1]:02X}{rgb2[2]:02X}"
                color_info = colors_map[filament_type].get(combo)
            if not color_info:
                color_info = colors_map[filament_type].get(rgb_hex)
        if color_info:
            print(f"Block 5 - Color Name: {color_info['name']}")
            print(f"Block 5 - Color Code: {color_info['code']}")
        # Primary swatch always
        print("Block 5 - Primary Color Swatch:", end=" ")
        print_color_block(r1, g1, b1)
        print(f"Block 5 - Spool Weight: {weight} g")
        print(f"Block 5 - Filament Diameter: {diameter:.2f} mm")

    # Block 6: Drying & Temperature
    b6 = blocks.get(6)
    if b6:
        dtg = le_uint16(b6[0:2])
        dth = le_uint16(b6[2:4])
        btt = le_uint16(b6[4:6])
        btemp = le_uint16(b6[6:8])
        hot_max = le_uint16(b6[8:10])
        hot_min = le_uint16(b6[10:12])
        print(f"Block 6 - Drying Temp: {dtg} °C, Time: {dth} h")
        print(f"Block 6 - Bed Temp Type: {btt}, Temp: {btemp} °C")
        print(f"Block 6 - Hotend Max/Min: {hot_max}/{hot_min} °C")

    # Block 8: X-Cam & Nozzle
    b8 = blocks.get(8)
    if b8:
        cam = "".join(f"{byte:02X}" for byte in b8[:12])
        noz = le_float(b8[12:16])
        print(f"Block 8 - X-Cam Info: {cam}")
        print(f"Block 8 - Nozzle Diameter: {noz:.2f} mm")

    # Block 9: Tray UID hex
    b9 = blocks.get(9)
    if b9:
        uid_hex = " ".join(f"{byte:02X}" for byte in b9 if byte is not None)
        print(f"Block 9 - Tray UID: {uid_hex}")

    # Block 10: Spool Width
    b10 = blocks.get(10)
    if b10:
        sw = le_uint16(b10[4:6])
        print(f"Block 10 - Spool Width: {sw/10:.2f} mm")

    # Block 12: Production DateTime
    b12 = blocks.get(12)
    if b12:
        raw12 = bytes(b12).decode("ascii", errors="ignore").rstrip("\x00")
        print(f"Block 12 - Production DateTime: {raw12}")

    # Block 13: Short Production Date
    b13 = blocks.get(13)
    if b13:
        raw13 = bytes(b13).decode("ascii", errors="ignore").rstrip("\x00")
        print(f"Block 13 - Short Production Date: {raw13}")

    # Block 14: Filament Length
    b14 = blocks.get(14)
    if b14:
        length = le_uint16(b14[4:6])
        print(f"Block 14 - Filament Length: {length:.2f} m")

        # Block 16: Extra Color Info + swatch and gradient
    b16 = blocks.get(16)
    if b16:
        fmt_id = le_uint16(b16[0:2])
        color_count = le_uint16(b16[2:4])
        a2, b2, g2, r2 = (b16[i] or 0 for i in range(4, 8))
        rgba2_hex = f"{r2:02X}{g2:02X}{b2:02X}{a2:02X}"
        print(f"Block 16 - Format ID: {fmt_id:04X}")
        print(f"Block 16 - Color Count: {color_count}")
        if color_count > 1:
            print(f"Block 16 - Second Color RGBA: {rgba2_hex}")
            # Print solid swatch for second color
            print("Block 16 - Second Color Swatch:", end=" ")
            print_color_block(r2, g2, b2)
            # Also print gradient between primary and secondary
            if b5:
                r1, g1, b1, _ = (b5[i] or 0 for i in range(4))
                print("Block 16 - Color Gradient:", end=" ")
                print_color_gradient(r1, g1, b1, r2, g2, b2)


# Parse Flipper text dumps
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


# Parse Proxmark binary or JSON dumps
def parse_proxmark_dump(filepath):
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        header = {}
        card = data.get("Card", {})
        if "UID" in card:
            header["UID"] = ":".join(
                card["UID"][i : i + 2] for i in range(0, len(card["UID"]), 2)
            )
        for key in ("ATQA", "SAK"):
            header[key] = card[key] if key in card else None
        blocks = {}
        for num_str, hexstr in data.get("blocks", {}).items():
            try:
                num = int(num_str)
                blocks[num] = [
                    int(hexstr[i : i + 2], 16) for i in range(0, len(hexstr), 2)
                ]
            except ValueError:
                pass
        return header, blocks
    except (json.JSONDecodeError, UnicodeDecodeError):
        blocks = {}
        with open(filepath, "rb") as f:
            raw = f.read()
        for i in range(len(raw) // 16):
            blocks[i] = list(raw[i * 16 : (i + 1) * 16])
        return {}, blocks


# Main entry
def main():
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
    with open(args.colors_json, "r") as cj:
        colors_map = json.load(cj)
    fmt = args.format
    if not fmt:
        try:
            with open(args.filepath, "r") as f:
                first = f.readline()
                fmt = "flipper" if "Flipper NFC device" in first else None
        except (OSError, UnicodeDecodeError):
            fmt = None
    if not fmt:
        ext = os.path.splitext(args.filepath)[1].lower()
        fmt = "proxmark" if ext in (".bin", ".json") else "flipper"
    header, blocks = (parse_proxmark_dump if fmt == "proxmark" else parse_flipper_dump)(
        args.filepath
    )
    print_parsed(blocks, header, colors_map, args.filepath)


if __name__ == "__main__":
    main()
