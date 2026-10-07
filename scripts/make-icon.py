"""アプリアイコン（assets/icon.ico, assets/icon.png）を生成する。

図柄: 左から入った 1 本の経路が分岐点で複数の出口へ振り分けられる（= ルーター）。
各サイズを 4 倍で描いて縮小し、24px 以下は分岐を減らした簡略版にする。
"""

import math
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
SS = 4  # スーパーサンプリング倍率

BG_TOP = (20, 52, 110)
BG_BOTTOM = (16, 132, 150)
LINE = (255, 255, 255)
ACCENT = (255, 196, 64)


def gradient(size):
    img = Image.new("RGBA", (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            # 左上→右下の対角グラデーション
            t = (x + y) / (2 * (size - 1))
            px[x, y] = tuple(int(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOTTOM)) + (255,)
    return img


def arrow_head(d, tip, angle, length, width, fill):
    """先端 tip、向き angle の三角形の矢じり"""
    back = (tip[0] - length * math.cos(angle), tip[1] - length * math.sin(angle))
    nx, ny = -math.sin(angle) * width / 2, math.cos(angle) * width / 2
    d.polygon([tip, (back[0] + nx, back[1] + ny), (back[0] - nx, back[1] - ny)], fill=fill)


def draw(size):
    s = size * SS
    simple = size <= 24
    # 背景: 角丸の正方形（小サイズは余白を詰めて図柄を大きく）
    margin = s * (0.02 if simple else 0.04)
    radius = s * 0.22
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([margin, margin, s - margin, s - margin], radius=radius, fill=255)
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(gradient(s), (0, 0), mask)

    d = ImageDraw.Draw(img)
    lw = s * (0.11 if simple else 0.075)  # 線の太さ
    hub = (s * (0.36 if simple else 0.40), s * 0.50)  # 分岐点
    start = (s * 0.12, s * 0.50)
    # 小サイズは矢じりを控えめにして、2 本の矢の間に隙間を残す
    head_len, head_w = (lw * 1.5, lw * 2.2) if simple else (lw * 2.0, lw * 2.6)

    # 出口（右側）の端点。簡略版は 2 本、通常は 3 本
    ends = [(s * 0.88, s * 0.18), (s * 0.88, s * 0.82)] if simple else [(s * 0.84, s * 0.22), (s * 0.86, s * 0.50), (s * 0.84, s * 0.78)]

    d.line([start, hub], fill=LINE, width=int(lw))
    for end in ends:
        angle = math.atan2(end[1] - hub[1], end[0] - hub[0])
        # 線は矢じりの手前で止める
        stop = (end[0] - head_len * 0.8 * math.cos(angle), end[1] - head_len * 0.8 * math.sin(angle))
        d.line([hub, stop], fill=LINE, width=int(lw))
        arrow_head(d, end, angle, head_len, head_w, LINE)

    # 分岐点のノード（ルール評価の場所）を強調
    r = lw * (0.95 if simple else 1.45)
    d.ellipse([hub[0] - r, hub[1] - r, hub[0] + r, hub[1] + r], fill=ACCENT)
    if not simple:
        r2 = r * 0.45
        d.ellipse([hub[0] - r2, hub[1] - r2, hub[0] + r2, hub[1] + r2], fill=BG_TOP)
    # 入口の丸（線端を丸く）
    d.ellipse([start[0] - lw / 2, start[1] - lw / 2, start[0] + lw / 2, start[1] + lw / 2], fill=LINE)

    return img.resize((size, size), Image.LANCZOS)


def main():
    OUT.mkdir(exist_ok=True)
    images = {size: draw(size) for size in SIZES}
    images[256].save(OUT / "icon.png")
    # ICO は各サイズを個別に描いた画像をそのまま格納する
    images[256].save(OUT / "icon.ico", sizes=[(n, n) for n in SIZES], append_images=[images[n] for n in SIZES[:-1]])

    # 確認用: 全サイズを明暗 2 種の背景に並べたプレビュー
    w = sum(SIZES) + 12 * len(SIZES) + 12
    preview = Image.new("RGBA", (w, 2 * (256 + 24)), (245, 245, 245, 255))
    ImageDraw.Draw(preview).rectangle([0, 256 + 24, w, 2 * (256 + 24)], fill=(32, 32, 32, 255))
    for row in range(2):
        x = 12
        for n in SIZES:
            preview.alpha_composite(images[n], (x, row * (256 + 24) + 12 + (256 - n) // 2))
            x += n + 12
    preview.save(OUT / "icon-preview.png")
    print("generated:", ", ".join(str(p.relative_to(ROOT)) for p in sorted(OUT.iterdir())))


if __name__ == "__main__":
    main()
