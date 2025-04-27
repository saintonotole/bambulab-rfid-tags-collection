# BambuLab RFID Tag Parser & Spool Collection

This repository provides data for parsing and analyzing the RFID tags embedded in Bambu Lab filament spools.
You can use this data for research purposes, or clone it to compatible blank RFID Gen2/FUID tags.

## Repository Structure

- `parse_nfc_dump.py`  
  A Python script that parses NFC dump files (Flipper Zero `.nfc` text dumps or Proxmark binary dumps) to extract human-readable spool details:
  - Filament type and detailed type
  - Color RGBA values and lookup of color name & code
  - Spool weight, diameter, length
  - Production date/time
  - Drying and temperature recommendations

For detailed information on the tag data structure, see the [RFID Tag Guide](https://github.com/Bambu-Research-Group/RFID-Tag-Guide#tag-documentation).


- `filament_colors.json`  
  A JSON lookup table mapping filament types to their RGB hex codes, human-friendly color names, and official Bambu Lab color codes.

- `dumps/`  
  A collection of raw NFC dumps from Bambu Lab filament spools.

Contributions of new dump files or corrected color mappings are welcome!

## Usage

**Parse a single dump**
```bash
python parse_nfc_dump.py dumps/spool1.nfc --colors-json filament_colors.json
```

**Explicit format selection**
```bash
python parse_nfc_dump.py dumps/spool1.bin --format proxmark
```

Parsed output will display each block’s decoded fields, color swatches, and lookups for name & code.

## Contributing

1. Fork this repository.  
2. Add your new dump files under `dumps/` or update `filament_colors.json`.  
3. Submit a pull request describing your changes.
