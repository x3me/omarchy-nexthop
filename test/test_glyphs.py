"""Every glyph the plugin draws is the one its comment names.

Nerd Font icons are private-use codepoints: nothing in the source says what
picture one is except the comment beside it, and nothing checked that
comment. #13 shipped "nf-md-speedometer_medium" and "_slow" at U+F0FBE and
U+F0FBF, which are `format_text_rotation_up` and `_vertical` — an "A" with an
arrow on the bar — and the test written for them pinned the codepoints the
code already had, so it agreed with the mistake. The real ones are U+F0F85
and U+F0F86. This reads the glyph names out of the installed Nerd Font's own
`post` table and holds each commented glyph to them.

Stdlib only (the daemon's rule, kept for its tests). Skipped where there is
no Nerd Font to ask — the runner-like PATH has no fc-match, and CI has no
Nerd Font — so this is a check for the machine the plugin is developed on.
"""
import re
import shutil
import struct
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import REPO  # noqa: E402

PUA = re.compile("[\U000F0000-\U000FFFFD-]")
COMMENT = re.compile(r"//\s*nf-([a-z]+-[a-z0-9_]+)")


def glyph_names(path):
    """{codepoint: glyph name} from a TrueType font's cmap (format 12) and
    post (format 2) tables — the names Nerd Fonts patches in."""
    d = Path(path).read_bytes()
    tables = {}
    for i in range(struct.unpack(">H", d[4:6])[0]):
        tag, _, off, ln = struct.unpack(">4sIII", d[12 + 16 * i:28 + 16 * i])
        tables[tag.decode("latin1")] = (off, ln)
    if "cmap" not in tables or "post" not in tables:
        return {}
    cmap = {}
    off = tables["cmap"][0]
    for i in range(struct.unpack(">H", d[off + 2:off + 4])[0]):
        sub = off + struct.unpack(">I", d[off + 8 + 8 * i:off + 12 + 8 * i])[0]
        if struct.unpack(">H", d[sub:sub + 2])[0] != 12:
            continue
        for g in range(struct.unpack(">I", d[sub + 12:sub + 16])[0]):
            s, e, gid = struct.unpack(">III", d[sub + 16 + 12 * g:sub + 28 + 12 * g])
            for c in range(s, e + 1):
                cmap[c] = gid + (c - s)
    off, ln = tables["post"]
    if struct.unpack(">I", d[off:off + 4])[0] != 0x00020000:
        return {}
    count = struct.unpack(">H", d[off + 32:off + 34])[0]
    index = struct.unpack(">%dH" % count, d[off + 34:off + 34 + 2 * count])
    names, pos = [], off + 34 + 2 * count
    while pos < off + ln:
        size = d[pos]
        names.append(d[pos + 1:pos + 1 + size].decode("latin1"))
        pos += 1 + size
    return {c: names[index[g] - 258] for c, g in cmap.items()
            if g < count and index[g] >= 258 and index[g] - 258 < len(names)}


def commented_glyphs():
    """(file, line number, codepoint, name the comment claims)."""
    out = []
    for path in sorted(list(REPO.glob("*.qml")) + list(REPO.glob("*.js"))):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            chars, claim = PUA.findall(line), COMMENT.search(line)
            if len(chars) == 1 and claim:
                out.append((path.name, n, ord(chars[0]), claim.group(1)))
    return out


class GlyphsAreWhatTheySay(unittest.TestCase):
    def test_each_commented_glyph_is_the_named_icon(self):
        fc = shutil.which("fc-match")
        if not fc:
            self.skipTest("fc-match not on PATH")
        font = subprocess.run([fc, "-f", "%{file}", "monospace:charset=f04c5"],
                              capture_output=True, text=True).stdout.strip()
        names = glyph_names(font) if font else {}
        if names.get(0xF04C5) != "md-speedometer":
            self.skipTest("no Nerd Font with glyph names installed")
        found = commented_glyphs()
        self.assertGreater(len(found), 5)          # the scan itself works
        wrong = [f"{f}:{n} U+{c:X} says nf-{claim}, the font has "
                 f"{names.get(c)}" for f, n, c, claim in found
                 if names.get(c) != claim]
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
