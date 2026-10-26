#!/usr/bin/env python3
"""Frame raw App Store screenshots with a caption.

Reads fastlane/raw_screenshots/<locale>/*.png (fastlane snapshot output), puts
each one in a phone frame on AgePony's brand gradient under a headline and a
subline from fastlane/captions.json, and writes the result at the same pixel
size to fastlane/screenshots/<locale>/, which is what deliver uploads.

A screenshot is matched to its caption by the snapshot name at the end of its
file name ("iPhone 17 Pro Max-01Files.png" -> "01Files"). One without a
caption is skipped with a warning.

Usage: python3 tools/frame_screenshots.py   (needs Pillow: pip3 install pillow)
"""

import json
import os
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "fastlane" / "raw_screenshots"
OUT = ROOT / "fastlane" / "screenshots"
CAPTIONS = ROOT / "fastlane" / "captions.json"

# AgePonyColors.brandGradient: cyan top-left, teal, deep teal bottom-right.
CYAN = (0x38, 0xCF, 0xE8)
TEAL = (0x14, 0xB8, 0xB0)
DEEP = (0x0E, 0x7D, 0x7A)
INK = (0x0A, 0x4F, 0x4D)

BOLD_FONTS = [
    os.environ.get("FRAME_FONT_BOLD", ""),
    "/usr/share/fonts/opentype/inter/InterDisplay-Bold.otf",
    "/Library/Fonts/InterDisplay-Bold.otf",
    "/System/Library/Fonts/SFNSRounded.ttf",
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
]
REGULAR_FONTS = [
    os.environ.get("FRAME_FONT_REGULAR", ""),
    "/usr/share/fonts/opentype/inter/InterDisplay-Medium.otf",
    "/Library/Fonts/InterDisplay-Medium.otf",
    "/System/Library/Fonts/SFNS.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
]


def font(candidates, size):
    for path in candidates:
        if path and Path(path).exists():
            return ImageFont.truetype(path, size)
    sys.exit("No usable font found; set FRAME_FONT_BOLD and FRAME_FONT_REGULAR")


def gradient(w, h):
    """Diagonal three-stop gradient, top-left to bottom-right."""
    small_w, small_h = 66, 144  # computed small, then smoothly scaled up
    img = Image.new("RGB", (small_w, small_h))
    px = img.load()
    for y in range(small_h):
        for x in range(small_w):
            t = (x / (small_w - 1) + y / (small_h - 1)) / 2
            a, b, u = (CYAN, TEAL, t / 0.5) if t < 0.5 else (TEAL, DEEP, (t - 0.5) / 0.5)
            px[x, y] = tuple(round(a[i] + (b[i] - a[i]) * u) for i in range(3))
    return img.resize((w, h), Image.BICUBIC)


def wrap(draw, text, fnt, max_width):
    """Fewest lines that fit, with the words spread evenly across them, so a
    two-line headline never leaves one word on its own."""
    words = text.split()
    if not words:
        return []
    for count in range(1, len(words) + 1):
        best = None
        # every way to cut the words into `count` lines
        def cuts(start, left):
            if left == 1:
                yield [words[start:]]
                return
            for end in range(start + 1, len(words) - left + 2):
                for rest in cuts(end, left - 1):
                    yield [words[start:end]] + rest
        for split in cuts(0, count):
            lines = [" ".join(ws) for ws in split]
            widths = [draw.textlength(l, font=fnt) for l in lines]
            if max(widths) <= max_width and (best is None or max(widths) < best[0]):
                best = (max(widths), lines)
        if best:
            return best[1]
    return words


def rounded(img, radius):
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, img.width - 1, img.height - 1], radius=radius, fill=255)
    out = Image.new("RGBA", img.size, (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out


def frame(shot, caption):
    W, H = shot.size
    s = W / 1320  # every measure below is for a 1320 px wide canvas
    canvas = gradient(W, H).convert("RGBA")
    draw = ImageDraw.Draw(canvas)

    # Caption block, centred in a fixed band (room for two headline lines and
    # a subline), so the phone sits at the same place on every screenshot.
    head_font = font(BOLD_FONTS, round(96 * s))
    sub_font = font(REGULAR_FONTS, round(50 * s))
    margin = round(90 * s)
    head_step, sub_step, gap = round(112 * s), round(64 * s), round(18 * s)
    head = wrap(draw, caption["headline"], head_font, W - 2 * margin)
    sub = wrap(draw, caption.get("subline", ""), sub_font, W - 2 * margin)
    band_top, band_h = round(130 * s), 2 * head_step + gap + 2 * sub_step
    block_h = len(head) * head_step + (gap + len(sub) * sub_step if sub else 0)
    y = band_top + (band_h - block_h) // 2
    for line in head:
        lw = draw.textlength(line, font=head_font)
        draw.text(((W - lw) / 2, y), line, font=head_font, fill="white")
        y += head_step
    y += gap
    for line in sub:
        lw = draw.textlength(line, font=sub_font)
        draw.text(((W - lw) / 2, y), line, font=sub_font, fill=(255, 255, 255, 225))
        y += sub_step
    y = band_top + band_h

    # Phone: the screenshot inside a dark bezel, with a soft shadow.
    top = y + round(40 * s)
    bezel = round(26 * s)
    screen_h = H - top - round(90 * s) - 2 * bezel  # the whole phone, tab bar included
    screen_w = round(screen_h * W / H)
    max_w = W - 2 * round(110 * s)
    if screen_w > max_w:
        screen_w = max_w
        screen_h = round(screen_w * H / W)
    screen = rounded(shot.convert("RGB").resize((screen_w, screen_h), Image.LANCZOS), round(118 * s))
    body_w, body_h = screen_w + 2 * bezel, screen_h + 2 * bezel
    body = Image.new("RGBA", (body_w, body_h), (0, 0, 0, 0))
    ImageDraw.Draw(body).rounded_rectangle([0, 0, body_w - 1, body_h - 1], radius=round(140 * s), fill=(18, 22, 24, 255))
    body.alpha_composite(screen, (bezel, bezel))

    x = (W - body_w) // 2
    shadow = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle(
        [x, top + round(24 * s), x + body_w, top + round(24 * s) + body_h], radius=round(140 * s), fill=(*INK, 150))
    shadow = shadow.filter(ImageFilter.GaussianBlur(round(40 * s)))
    canvas.alpha_composite(shadow)
    canvas.alpha_composite(body, (x, top))
    return canvas.convert("RGB")


def main():
    captions = json.loads(CAPTIONS.read_text())
    if not RAW.exists():
        sys.exit(f"No raw screenshots at {RAW}; run `bundle exec fastlane ios screenshots` first")
    made = 0
    for locale_dir in sorted(p for p in RAW.iterdir() if p.is_dir()):
        out_dir = OUT / locale_dir.name
        out_dir.mkdir(parents=True, exist_ok=True)
        for png in sorted(locale_dir.glob("*.png")):
            key = png.stem.rsplit("-", 1)[-1]
            if key not in captions:
                print(f"skip {png.name}: no caption for {key!r}")
                continue
            framed = frame(Image.open(png), captions[key])
            framed.save(out_dir / png.name, optimize=True)
            made += 1
            print(f"framed {locale_dir.name}/{png.name}")
    print(f"{made} screenshots framed into {OUT}")


if __name__ == "__main__":
    main()
