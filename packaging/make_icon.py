"""Render the DarkWatch AI icon (same design as dashboard/icon.svg) with Pillow.

    python packaging/make_icon.py
      -> dashboard/icon.png (256 px), dashboard/favicon.ico, packaging/icon.ico (16-256 px)
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
S = 1024                      # draw at 4x the 256 design grid, then downscale
K = S / 256


def _bez(p0, p1, p2, p3, n=48):
    out = []
    for i in range(n + 1):
        t = i / n
        a, b, c, d = (1 - t) ** 3, 3 * t * (1 - t) ** 2, 3 * t * t * (1 - t), t ** 3
        out.append((a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0], a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]))
    return out


def _sc(pts):
    return [(x * K, y * K) for x, y in pts]


def _gradient(size, c0, c1, diagonal=True):
    w, h = size
    g = Image.new("RGB", size)
    px = g.load()
    for y in range(h):
        for x in range(w):
            t = ((x + y) / (w + h)) if diagonal else y / h
            px[x, y] = tuple(int(c0[i] + (c1[i] - c0[i]) * t) for i in range(3))
    return g


def render() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # rounded square background, violet gradient
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([8 * K, 8 * K, 248 * K, 248 * K], radius=56 * K, fill=255)
    img.paste(_gradient((S, S), (0x7C, 0x5C, 0xFF), (0x24, 0x1A, 0x5C)), (0, 0), mask)
    d = ImageDraw.Draw(img)
    # shield
    shield = [(128, 34), (204, 62), (204, 124)] + _bez((204, 124), (204, 170), (172, 205), (128, 222))[1:] \
        + _bez((128, 222), (84, 205), (52, 170), (52, 124))[1:] + [(52, 62)]
    d.polygon(_sc(shield), fill=(0x0E, 0x11, 0x18, 255))
    d.line(_sc(shield + [shield[0], shield[1]]), fill=(0xA2, 0x8B, 0xFF, 255), width=int(6 * K), joint="curve")
    # eye outline
    eye = _bez((74, 128), (92, 100), (108, 90), (128, 90)) + _bez((128, 90), (148, 90), (164, 100), (182, 128))[1:] \
        + _bez((182, 128), (164, 156), (148, 166), (128, 166))[1:] + _bez((128, 166), (108, 166), (92, 156), (74, 128))[1:]
    d.line(_sc(eye + [eye[0], eye[1]]), fill=(0xE6, 0xE8, 0xEE, 255), width=int(7 * K), joint="curve")
    # iris: radial violet -> red core
    r = 25 * K
    iris = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    idraw = ImageDraw.Draw(iris)
    steps = 60
    for i in range(steps, 0, -1):
        t = i / steps
        c0, c1 = (0xFF, 0x4D, 0x6D), (0x7C, 0x5C, 0xFF)
        col = tuple(int(c0[j] + (c1[j] - c0[j]) * t) for j in range(3))
        rr = r * t
        idraw.ellipse([128 * K - rr, 128 * K - rr, 128 * K + rr, 128 * K + rr], fill=col + (255,))
    img.alpha_composite(iris)
    d = ImageDraw.Draw(img)
    d.pieslice([128 * K - r, 128 * K - r, 128 * K + r, 128 * K + r], start=-90, end=-28, fill=(0xE6, 0xE8, 0xEE, 140))
    d.ellipse([119 * K, 119 * K, 137 * K, 137 * K], fill=(0x0B, 0x0D, 0x12, 255))
    d.ellipse([133 * K, 115 * K, 141 * K, 123 * K], fill=(255, 255, 255, 255))
    return img


def main() -> None:
    big = render().filter(ImageFilter.SMOOTH)
    png = big.resize((256, 256), Image.LANCZOS)
    (ROOT / "dashboard").mkdir(exist_ok=True)
    png.save(ROOT / "dashboard" / "icon.png", optimize=True)
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    png.save(ROOT / "packaging" / "icon.ico", sizes=sizes)
    png.save(ROOT / "dashboard" / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    print("icons written")


if __name__ == "__main__":
    main()
