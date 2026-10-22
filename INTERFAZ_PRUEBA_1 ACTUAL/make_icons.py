import math, os
from PIL import Image, ImageDraw

os.makedirs("static", exist_ok=True)
size = 192
img = Image.new("RGB", (size, size), "#E45176")
d = ImageDraw.Draw(img)
c, R, r = size / 2, size * 0.17, size * 0.13
for i in range(6):
    a = math.radians(i * 60)
    x, y = c + R * math.cos(a), c + R * math.sin(a)
    d.ellipse([x - r, y - r, x + r, y + r], fill="white")
k = size * 0.09
d.ellipse([c - k, c - k, c + k, c + k], fill="#F5BD6E")
img.save("static/icon-193.png")