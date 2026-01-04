# Khao2
```bash
██╗  ██╗    ██████╗ 
██║ ██╔╝    ╚════██╗
█████╔╝      █████╔╝
██╔═██╗     ██╔═══╝ 
██║  ██╗    ███████╗
╚═╝  ╚═╝    ╚══════╝
```

**Every single bit.**

Easy to use, infromative and comprehensive steganalysis suite.

This is a CLI tool for my SaaS sidehustle (khao2.com) for steganalysis.

## Installation

```bash
pip install -e .
```

## Usage

Get a token:
- Sign up at app.khao2.com
- Create an API key in the API Keys tab

Configure your API token:
```bash
k2 token set k2_yourtokenhere32characterslower
```

Configure API endpoint:
```bash
k2 endpoint set https://api.khao2.com
```

Analyze an image:
```bash
k2 dig image.png
```

Watch scan progress in real-time:
```bash
k2 dig image.png --watch
```

Get scan results by ID:
```bash
k2 get <scan-id>
```

## Info
This is a personal project turned SaaS side hustle, I originally built this for my own CTF challenges with no intention of making it a product.

## Pricing
People may say 5 scans a month for free is too little, but please bear in mind that these statistical scans are sequential by nature and take upwards of + minutes where they run on Modal.com HPC.

## Cool stuff

- It caught J-UNIWARD at 0.2 BPP
- Very good at catching LSB
- Uses ML to classify all statistical tests for a human readable view

# Example CLI output:

```bash
██╗  ██╗    ██████╗
██║ ██╔╝    ╚════██╗
█████╔╝      █████╔╝
██╔═██╗     ██╔═══╝
██║  ██╗    ███████╗
╚═╝  ╚═╝    ╚══════╝

KHAO2 IMAGE FORENSICS | Every little bit.

✅ ANALYSIS COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERDICT: BENIGN
Possibility: 8%
Confidence: 85.0%

File: test.png
Size: 88 bytes | 1x1 | PNG

SSDEEP: 3:yionv//thPlE+tnMysyxdk/Slc+0kxQcnd6vtjp:6v/lhPfZMys+k/WT0krnd6vdp
SHA512: cd96b0688ad40f6b8ea0f2dd5529ae14d0037fbf8b30e1a1d0fd1a81a16e4c4305c95f1673aee7808a618c70ce4d0d4706c31dc7fb8cf4deab39c8ce584d7535
SHA256: 39768f51d067905ee91c1422fe26ea2cc978ff0ac12bb61b3878f094c2cd1db3
MD5: b34c91ec15a592d974131f02c1f05cb6

ENGINES: 329/339 completed | 10 failed
Runtime: 373489ms | 29.84K FLOPs

FILE INTEGRITY
├─ Format: PNG image, 1 x 1, 8-bit/color RGBA, non-interlaced
├─ Mode: RGBA

STATISTICAL ANALYSIS
├─ Entropy: -0.0
├─ Size Score: 0.09
└─ Strings Found: 0

ANOMALIES DETECTED: 1 (85.0% CONFIDENCE)
! #082_CLA Perfect lag correlation in a 1x1 image, likely trivial and not indicative of hidden data
  Confidence: 50.0% | Anomaly Value: 10.0

IDENTIFIED MEDIUM: none
IDENTIFIED VECTOR: No hidden data detected; image size and entropy too low for embedding
TECHNIQUE CARDINALS: LSB Replacement,PNG ancillary chunks,Palette LSB

RECOMMENDED NEXT STEPS:
  Run pngcheck and exiftool to list all PNG chunks, use StegDetect or zsteg on the file, and re‑run binwalk with deeper recursion to confirm no hidden payloads.

POTENTIAL FALSE NEGATIVE REASONS:
  • Extremely small carrier (30% likelihood)
  • Stego in unparsed metadata (25% likelihood)
  • Custom proprietary embedding (20% likelihood)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Development

Run tests:
```bash
pytest
```

Install in development mode:
```bash
pip install -e .
