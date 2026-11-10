"""FW Config Sanitizer — light Tkinter UI to redact secrets from firewall configs.

Supports: OPNsense/pfSense XML, FortiGate CLI, MikroTik RouterOS (.rsc), Cisco IOS.
Auto-detects the vendor per file. Engine code lives under engines/ (copied from
the firewall-doc-generator so this app is self-contained).

Run:  python sanitize_ui.py

UI is Persian, right-to-left. Tk has no bidi/shaping engine and no rounded
chrome, so:

* Persian shown in Tk widgets is pre-shaped with arabic-reshaper + python-bidi
  (see `rtl()`); the layout is mirrored right-to-left.
* Panels, buttons, fields, switches and scrollbars are rendered to anti-aliased
  images with PIL and blitted onto small Canvases; ttk widgets (Treeview, Entry,
  Text) do the actual work inside them.

Native dialogs (file/message boxes) are drawn by the OS and take raw Persian.
"""

from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

sys.path.insert(0, str(Path(__file__).resolve().parent))

import arabic_reshaper  # noqa: E402
from bidi.algorithm import get_display  # noqa: E402

try:
    from PIL import Image, ImageDraw, ImageFont, ImageTk

    _PIL = True
except ImportError:  # chrome degrades to flat fills, app still runs
    _PIL = False

from engines.detect import detect_vendor  # noqa: E402
from engines.mapping import TokenMapper  # noqa: E402
from engines.fortigate.redactor import redact_fortigate_config  # noqa: E402
from engines.mikrotik.redactor import redact_mikrotik_config  # noqa: E402
from engines.cisco.redactor import redact_cisco_config  # noqa: E402
from engines.pfsense_redactor import PfSenseRedactor  # noqa: E402


def rtl(text: str) -> str:
    """Reshape + reorder a string for display in a Tk widget (no bidi engine).

    Latin-only strings pass through unchanged. Only for on-screen Tk text;
    never for filenames, tokens, or values written to disk.
    """
    if not text:
        return text
    return get_display(arabic_reshaper.reshape(text))


VENDOR_LABELS = {
    "opnsense": "OPNsense / pfSense",
    "fortigate": "FortiGate",
    "mikrotik": "MikroTik (RouterOS)",
    "cisco": "Cisco IOS",
    "unknown": "ناشناخته",
}

# Native file dialogs render RTL themselves -> raw Persian.
FILE_TYPES = [
    ("همهٔ فایل‌های پشتیبانی‌شده", "*.xml *.conf *.rsc *.txt"),
    ("OPNsense/pfSense", "*.xml"),
    ("FortiGate", "*.conf *.txt"),
    ("MikroTik", "*.rsc"),
    ("Cisco IOS", "*.txt *.conf"),
    ("همهٔ فایل‌ها", "*.*"),
]


# ── Palette ────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Palette:
    """Brand: پویش داده نوین — blue #2853FF / orange #FE4D00 (sampled from logo)."""

    base: str = "#F2F4F8"         # cool neutral surface; brand blue stays an accent
    card: str = "#FFFFFF"         # panel face
    card_hi: str = "#F3F5F9"      # hovered row / control hover
    field: str = "#F8FAFC"        # inputs (slightly inset)
    track: str = "#E1E5EC"        # switch off / rail track
    text: str = "#111827"
    text_muted: str = "#4B5563"
    text_dim: str = "#8A94A6"
    accent: str = "#2853FF"       # brand blue: every interactive element
    accent_hi: str = "#1F46E6"    # hover
    accent_dim: str = "#1738C4"   # press / selection
    brand_orange: str = "#FE4D00"  # logo triangle: progress + brand mark only
    ok: str = "#0E9F6E"
    warn: str = "#C2410C"
    danger: str = "#D93A4A"


P = Palette()

# Single radius scale: surfaces 12, controls and inputs 8. Switches and rails
# stay round because they are switches and rails, not boxes.
R_SURFACE = 12
R_CONTROL = 8

HAIRLINE = "#E4E7EC"
HAIRLINE_HI = "#CDD4DE"
_SS = 2               # supersample factor for anti-aliasing


def _rgb(hex_color: str) -> tuple[int, int, int]:
    hex_color = hex_color.lstrip("#")
    return tuple(int(hex_color[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


def _mix(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))  # type: ignore[return-value]


def _hex(rgb: tuple[int, int, int]) -> str:
    return "#%02x%02x%02x" % rgb


# ── Fonts ──────────────────────────────────────────────────────────
FONT_DIR = Path(__file__).resolve().parent / "fonts"
UI_FONT_CANDIDATES = ("Vazirmatn", "Vazirmatn FD NL", "Segoe UI", "Tahoma")
MONO_FAMILY = "Consolas" if sys.platform == "win32" else "monospace"
FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "Tahoma"
FONTS: dict[str, tuple] = {
    "xs": (FONT_FAMILY, 10),
    "sm": (FONT_FAMILY, 11),
    "base": (FONT_FAMILY, 12),
    "lg": (FONT_FAMILY, 14, "bold"),
    "xl": (FONT_FAMILY, 18, "bold"),
}
MONO = (MONO_FAMILY, 10)
PAD = {"xs": 4, "sm": 8, "md": 16, "lg": 24}


def _load_bundled_fonts() -> int:
    """Register fonts/*.ttf with the OS (Windows: process-private) so Tk and PIL
    can use them without a system install. Returns the number registered."""
    if sys.platform != "win32" or not FONT_DIR.is_dir():
        return 0
    import ctypes

    FR_PRIVATE = 0x10
    gdi = ctypes.windll.gdi32
    count = 0
    for ttf in FONT_DIR.glob("*.ttf"):
        try:
            if gdi.AddFontResourceExW(str(ttf), FR_PRIVATE, 0):
                count += 1
        except OSError:
            pass
    return count


def _install_fonts(root: tk.Tk) -> None:
    """Choose the first available bundled family and rebuild the FONTS map.

    Tk exposes only Regular and Bold of Vazirmatn, so hierarchy comes from size,
    color and space rather than from a weight axis.
    """
    global FONT_FAMILY, FONTS
    available = set(tkfont.families(root))
    FONT_FAMILY = next((f for f in UI_FONT_CANDIDATES if f in available), "Tahoma")
    FONTS = {
        "xs": (FONT_FAMILY, 10),
        "sm": (FONT_FAMILY, 11),
        "base": (FONT_FAMILY, 12),
        "lg": (FONT_FAMILY, 14, "bold"),
        "xl": (FONT_FAMILY, 18, "bold"),
    }


_BUNDLED_FONTS_LOADED = _load_bundled_fonts()


def _font(spec: str = "base", *, bold: bool = False, mono: bool = False) -> tkfont.Font:
    if mono:
        return tkfont.Font(family=MONO_FAMILY, size=MONO[1])
    family, size, *rest = FONTS[spec]
    weight = "bold" if (bold or (rest and rest[0] == "bold")) else "normal"
    return tkfont.Font(family=family, size=size, weight=weight)


def _ttf(size: int, *, bold: bool = False):
    """PIL-side font for baked text (chips)."""
    if not _PIL:
        return None
    for name in ("Vazirmatn-Bold.ttf" if bold else "Vazirmatn-Medium.ttf",
                 "Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf"):
        path = FONT_DIR / name
        if path.exists():
            try:
                return ImageFont.truetype(str(path), size * _SS)
            except OSError:
                return None
    return None


def _has_persian(text: str) -> bool:
    return any("؀" <= ch <= "ۿ" for ch in text)


# ── Image cache + PIL chrome ───────────────────────────────────────
_CACHE: "OrderedDict[tuple, object]" = OrderedDict()
_CACHE_MAX = 240


def _cached(key: tuple, make):
    img = _CACHE.get(key)
    if img is not None:
        _CACHE.move_to_end(key)
        return img
    img = _CACHE[key] = make()
    if len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)  # oldest; widgets re-request on next <Configure>
    return img


def _card_photo(w: int, h: int, radius: int, *, fill: str = P.card,
                ring: str = HAIRLINE):
    """A cached panel face: rounded fill + 1px hairline. Flat by design."""
    key = ("card", w, h, radius, fill, ring)

    def make():
        if not _PIL or w < 6 or h < 6:
            return None
        w_s, h_s = w * _SS, h * _SS
        img = Image.new("RGBA", (w_s, h_s), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        box = (0, 0, w_s - 1, h_s - 1)
        d.rounded_rectangle(box, radius * _SS, fill=_rgb(fill))
        d.rounded_rectangle(box, radius * _SS, outline=_rgb(ring) + (255,), width=_SS)
        return ImageTk.PhotoImage(img.resize((w, h), Image.LANCZOS))

    return _cached(key, make)


def _shape_photo(w: int, h: int, radius: int, fill: tuple[int, int, int],
                 ring: tuple[int, int, int] | None = None, ring_alpha: int = 0):
    """A cached solid shape (button face, switch track, rail) with optional ring."""
    def make():
        if not _PIL or w < 4 or h < 4:
            return None
        w_s, h_s = w * _SS, h * _SS
        img = Image.new("RGBA", (w_s, h_s), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        box = (0, 0, w_s - 1, h_s - 1)
        d.rounded_rectangle(box, radius * _SS, fill=fill)
        if ring is not None and ring_alpha:
            d.rounded_rectangle(box, radius * _SS, outline=ring + (ring_alpha,), width=_SS)
        return ImageTk.PhotoImage(img.resize((w, h), Image.LANCZOS))

    return _cached(("shape", w, h, radius, fill, ring, ring_alpha), make)


def _dot_photo(diameter: int, color: str):
    def make():
        if not _PIL:
            return None
        s = diameter * _SS
        img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        ImageDraw.Draw(img).ellipse((0, 0, s - 1, s - 1), fill=_rgb(color) + (255,))
        return ImageTk.PhotoImage(img.resize((diameter, diameter), Image.LANCZOS))

    return _cached(("dot", diameter, color), make)


PUBLIC_DIR = Path(__file__).resolve().parent / "public"
LOGO_PATH = PUBLIC_DIR / "PDNSoft (2).png"
QR_PATH = PUBLIC_DIR / "image (23).png"
# the cube sits baked in the QR's centre — crisp at small sizes for the header mark
LOGO_MARK_CROP = (337, 337, 637, 637)
QR_BBOX = (52, 52, 921, 921)  # QR modules only, without the baked white margin


def _qr_photo(size: int):
    """QR at `size` px with the too-thin baked margin replaced by a real quiet zone."""
    key = ("qr", size)

    def make():
        if not _PIL or not QR_PATH.exists():
            return None
        try:
            img = Image.open(QR_PATH).convert("RGBA").crop(QR_BBOX)
        except OSError:
            return None
        c = img.size[0]
        pad = int(c * 0.14)  # ~4 modules of quiet zone
        canvas = Image.new("RGBA", (c + pad * 2, c + pad * 2), (255, 255, 255, 255))
        canvas.paste(img, (pad, pad))
        s = size * _SS
        return ImageTk.PhotoImage(canvas.resize((s, s), Image.LANCZOS))

    return _cached(key, make)


def _brand_photo(path: Path, size: int, *, radius: int | None = None,
                 crop: tuple[int, int, int, int] | None = None, clean: bool = False):
    """Cached logo / QR image at `size` px, optionally cropped and rounded.

    clean: key out the white backing and the QR's black modules surrounding the
    baked-in cube, leaving the mark on transparency.
    """
    key = ("brand", path.name, size, radius, crop, clean)

    def make():
        if not _PIL or not path.exists():
            return None
        try:
            img = Image.open(path).convert("RGBA")
        except OSError:
            return None
        if crop:
            img = img.crop(crop)
        if clean:
            px = img.load()
            for y in range(img.size[1]):
                for x in range(img.size[0]):
                    r, g, b, a = px[x, y]
                    spread = max(r, g, b) - min(r, g, b)
                    # neutral white backing, or neutral black QR modules -> gone
                    if spread < 26 and (min(r, g, b) > 198 or max(r, g, b) < 215):
                        px[x, y] = (r, g, b, 0)
        side = min(img.size)
        img = img.crop((0, 0, side, side))
        s = size * _SS
        img = img.resize((s, s), Image.LANCZOS)
        if radius is not None:
            mask = Image.new("L", img.size, 0)
            ImageDraw.Draw(mask).rounded_rectangle(
                (0, 0, s - 1, s - 1), radius * _SS, fill=255)
            img.putalpha(mask)
        return ImageTk.PhotoImage(img.resize((size, size), Image.LANCZOS))

    return _cached(key, make)


STATUS_COLORS = {"ok": P.ok, "failed": P.danger, "pending": P.text_muted, "running": P.warn}


def _chip_photo(vendor: str, status: str, w: int = 182, h: int = 24):
    """Vendor pill + status dot baked as one image for the Treeview #0 column
    (a ttk.Treeview row has room for exactly one image)."""
    key = ("chip", vendor, status, w, h)

    def make():
        if not _PIL:
            return None
        w_s, h_s = w * _SS, h * _SS
        img = Image.new("RGBA", (w_s, h_s), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((0, 0, w_s - 1, h_s - 1), h_s // 2, fill=(0, 0, 0, 12))
        label = VENDOR_LABELS.get(vendor, vendor)
        shown = rtl(label) if _has_persian(label) else label
        font = _ttf(10)
        if font is not None:
            d.text((14 * _SS, h_s // 2), shown, font=font,
                   fill=_rgb(P.text) + (208,), anchor="lm")
        dot = 9 * _SS
        cx = w_s - 16 * _SS
        d.ellipse((cx - dot // 2, h_s // 2 - dot // 2, cx + dot // 2, h_s // 2 + dot // 2),
                  fill=_rgb(STATUS_COLORS.get(status, P.text_muted)))
        return ImageTk.PhotoImage(img.resize((w, h), Image.LANCZOS))

    return _cached(key, make)


# ── Easing ─────────────────────────────────────────────────────────
def _ease_out(t: float) -> float:
    return 1.0 - (1.0 - t) ** 3


class _Animator:
    """Tiny eased value driver. Animates nothing but redraws: no layout motion."""

    def __init__(self, widget: tk.Misc, duration: int = 150, step: int = 16):
        self.widget = widget
        self.duration = duration
        self.step = step
        self._job = None

    def run(self, on_frame) -> None:
        self.cancel()
        start = self.widget.tk.call("clock", "milliseconds")

        def tick():
            elapsed = self.widget.tk.call("clock", "milliseconds") - start
            t = elapsed / self.duration
            if t >= 1.0:
                on_frame(1.0)
                self._job = None
                return
            on_frame(_ease_out(t))
            self._job = self.widget.after(self.step, tick)

        tick()

    def cancel(self) -> None:
        if self._job is not None:
            try:
                self.widget.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None


# ── Widgets ────────────────────────────────────────────────────────
class Island(tk.Frame):
    """A flat panel: rounded face + 1px hairline on a lowered Canvas, with a
    normal frame body on top carrying the children."""

    def __init__(self, parent, *, radius: int = R_SURFACE, pad: int = 16,
                 fill: str = P.card, ring: str = HAIRLINE):
        super().__init__(parent, bg=P.base)
        self._radius = radius
        self._fill = fill
        self._ring = ring
        # created before `body`, so it already sits underneath (Canvas.lower is the
        # tag method, not stacking)
        self._canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=P.base, takefocus=0)
        self._canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self._img_id = None
        self.body = tk.Frame(self, bg=fill)
        self.body.pack(fill="both", expand=True, padx=pad, pady=pad)
        self.bind("<Configure>", self._redraw)

    def _redraw(self, _event=None) -> None:
        w, h = self.winfo_width(), self.winfo_height()
        if w < 12 or h < 12:
            return
        img = _card_photo(w, h, self._radius, fill=self._fill, ring=self._ring)
        if img is None:
            self._canvas.delete("all")
            self._canvas.configure(bg=self._fill)
            return
        if self._img_id is None:
            self._img_id = self._canvas.create_image(0, 0, anchor="nw", image=img)
        else:
            self._canvas.itemconfigure(self._img_id, image=img)


class Button(tk.Canvas):
    """Rectangular button, 8px radius, with eased fill/text transitions."""

    # kind: (fill normal, fill hover, fill press, text normal, text hover, ring alpha)
    KINDS = {
        "primary": (P.accent, P.accent_hi, P.accent_dim, "#FFFFFF", "#FFFFFF", 0),
        "ghost": (P.card, P.card_hi, "#E9EDF3", P.text, P.text, 255),
        "quiet": (P.card, P.card_hi, "#E9EDF3", P.text_muted, P.text, 0),
    }

    def __init__(self, parent, text: str, command=None, *, kind: str = "ghost",
                 glyph: str = "", pad: tuple[int, int] = (16, 8), bg: str = P.card,
                 width: int | None = None):
        self._label_font = _font("base", bold=(kind == "primary"))
        self._label = (glyph + "  " if glyph else "") + rtl(text)
        w = width or (self._label_font.measure(self._label) + pad[0] * 2)
        h = self._label_font.metrics("linespace") + pad[1] * 2
        super().__init__(parent, width=w, height=h, highlightthickness=0, bd=0,
                         bg=bg, cursor="hand2" if command else "arrow", takefocus=1)
        self.command = command
        self._bw, self._bh, self._kind, self._bg = w, h, kind, bg
        self._anim = _Animator(self, 150)
        self._focus = False
        self._pressed = False
        self._enabled = True
        self._hover = False

        self._img_id = self.create_image(2, 0, anchor="nw")
        self._txt_id = self.create_text(w // 2, h // 2, text=self._label,
                                        font=self._label_font, fill=P.text_muted)
        self._render(0.0)

        self.bind("<Enter>", lambda e: self._to(1.0))
        self.bind("<Leave>", lambda e: (self._to(0.0), self._press_off()))
        self.bind("<Button-1>", self._press)
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<FocusIn>", lambda e: self._focus_change(True))
        self.bind("<FocusOut>", lambda e: self._focus_change(False))
        self.bind("<Return>", lambda e: self._fire())
        self.bind("<space>", lambda e: self._fire())

    # -- state
    def _to(self, target: float) -> None:
        if not self._enabled:
            return
        self._hover = target > 0.5
        self._anim.run(lambda t: self._render(t))

    def _press_off(self) -> None:
        if self._pressed:
            self._pressed = False
            self.move(self._txt_id, 0, -1)
            self._render(0.0)

    def _focus_change(self, on: bool) -> None:
        self._focus = on
        self._render(1.0 if self._hover else 0.0)

    def _press(self, _event=None) -> None:
        if not self._enabled:
            return
        self._pressed = True
        self.move(self._txt_id, 0, 1)
        self._render(1.0)

    def _release(self, event) -> None:
        if not self._pressed:
            return
        self._pressed = False
        self.move(self._txt_id, 0, -1)
        inside = event is None or (0 <= event.x <= self._bw and 0 <= event.y <= self._bh)
        self._render(1.0 if inside else 0.0)
        if inside and self._enabled and self.command is not None:
            self.command()

    def _fire(self, _event=None) -> None:
        if self._enabled and self.command is not None:
            self.command()

    def configure_state(self, state: str) -> None:
        self._enabled = state != "disabled"
        if not self._enabled:
            self._pressed = False
        self.configure(cursor="hand2" if (self._enabled and self.command) else "arrow")
        self._render(0.0)

    # -- paint
    def _render(self, t: float) -> None:
        t = round(t * 10) / 10  # quantised: bounds the image cache
        fill_n, fill_h, fill_p, txt_n, txt_h, ring = self.KINDS[self._kind]
        fill = _mix(_rgb(fill_n), _rgb(fill_h), t)
        text = _hex(_mix(_rgb(txt_n), _rgb(txt_h), t))
        if self._pressed:
            fill = _rgb(fill_p)
        if not self._enabled:
            fill = _mix(_rgb(fill_n), _rgb(self._bg), 0.78)
            text = P.text_dim
        ring_color = _rgb(P.accent) if self._focus else _rgb(HAIRLINE_HI)
        ring_alpha = 255 if self._focus else ring
        img = _shape_photo(self._bw - 4, self._bh, R_CONTROL, fill, ring_color, ring_alpha)
        if img is None:
            self.configure(bg=_hex(fill))
        else:
            self.itemconfigure(self._img_id, image=img)
        self.itemconfigure(self._txt_id, fill=text)


class Toggle(tk.Frame):
    """Canvas-drawn switch bound to a BooleanVar (replaces ttk.Checkbutton)."""

    W, H = 40, 22

    def __init__(self, parent, variable: tk.BooleanVar, text: str, *, bg: str = P.card,
                 command=None):
        super().__init__(parent, bg=bg)
        self.var = variable
        self.command = command
        self._anim = _Animator(self, 140)
        self._t = 1.0 if variable.get() else 0.0
        self._hover = False
        self._enabled = True

        self.canvas = tk.Canvas(self, width=self.W, height=self.H, highlightthickness=0,
                                bd=0, bg=bg, cursor="hand2", takefocus=1)
        self.canvas.pack(side="right")
        self._track = self.canvas.create_image(0, 0, anchor="nw")
        self._knob = self.canvas.create_image(0, 0, anchor="nw")
        self.label = tk.Label(self, text=rtl(text), bg=bg, fg=P.text, font=FONTS["sm"],
                              cursor="hand2", anchor="e")
        self.label.pack(side="right", padx=(0, 10))

        for w in (self, self.canvas, self.label):
            w.bind("<Button-1>", self._click)
        self.canvas.bind("<Enter>", lambda e: self._set_hover(True))
        self.canvas.bind("<Leave>", lambda e: self._set_hover(False))
        self.label.bind("<Enter>", lambda e: self._set_hover(True))
        self.label.bind("<Leave>", lambda e: self._set_hover(False))
        self.canvas.bind("<Return>", self._click)
        self.canvas.bind("<space>", self._click)
        self._paint()

    def _set_hover(self, on: bool) -> None:
        if not self._enabled:
            return
        self._hover = on
        self._paint()

    def _click(self, _event=None) -> None:
        if not self._enabled:
            return
        self.var.set(not self.var.get())
        target = 1.0 if self.var.get() else 0.0
        start = self._t

        def frame(u):
            self._paint(start + (target - start) * u)

        self._anim.run(frame)
        if self.command is not None:
            self.command()

    def get(self) -> bool:
        return bool(self.var.get())

    def set(self, value: bool) -> None:
        self.var.set(bool(value))
        self._t = 1.0 if value else 0.0
        self._paint()

    def configure_state(self, state: str) -> None:
        self._enabled = state != "disabled"
        cursor = "hand2" if self._enabled else "arrow"
        self.canvas.configure(cursor=cursor)
        self.label.configure(fg=P.text if self._enabled else P.text_dim, cursor=cursor)
        self._paint()

    def _paint(self, t: float | None = None) -> None:
        if t is not None:
            self._t = t
        tq = round(self._t * 12) / 12
        on_color = P.accent_hi if self._hover else P.accent
        track = _mix(_rgb(P.track), _rgb(on_color), tq)
        if not self._enabled:
            track = _mix(track, _rgb(P.card), 0.55)
        img = _shape_photo(self.W, self.H, self.H // 2, track,
                          _rgb(HAIRLINE_HI), 40 if self._hover else 0)
        if img is not None:
            self.canvas.itemconfigure(self._track, image=img)
        else:
            self.canvas.configure(bg=_hex(track))
        d = self.H - 6
        knob = _dot_photo(d, "#FFFFFF" if self._enabled else "#B9C1D2")
        self.canvas.coords(self._knob, 3 + self._t * (self.W - d - 6), 3)
        if knob is not None:
            self.canvas.itemconfigure(self._knob, image=knob)
            self.canvas.tag_raise(self._knob)


class Field(tk.Frame):
    """Rounded input well with a borderless Entry inside and an accent focus ring."""

    def __init__(self, parent, *, textvariable=None, width: int | None = None,
                 bg: str = P.card):
        super().__init__(parent, bg=bg)
        self._canvas = tk.Canvas(self, height=36, highlightthickness=0, bd=0, bg=bg, takefocus=0)
        self._canvas.pack(fill="both", expand=True)
        if width:
            self._canvas.configure(width=width)
        self._img_id = None
        self._focus = False
        self.entry = tk.Entry(self._canvas, bd=0, highlightthickness=0, relief="flat",
                              bg=P.field, fg=P.text, insertbackground=P.text,
                              selectbackground=P.accent_dim, selectforeground="#FFFFFF",
                              font=FONTS["base"], textvariable=textvariable,
                              disabledbackground=P.field, disabledforeground=P.text_dim)
        self._win = self._canvas.create_window(12, 18, anchor="w", window=self.entry)
        self._canvas.bind("<Configure>", self._redraw)
        self.entry.bind("<FocusIn>", lambda e: self._set_focus(True))
        self.entry.bind("<FocusOut>", lambda e: self._set_focus(False))

    def _set_focus(self, on: bool) -> None:
        self._focus = on
        self._redraw()

    def _redraw(self, _event=None) -> None:
        w, h = self._canvas.winfo_width(), self._canvas.winfo_height()
        if w < 8 or h < 8:
            return
        ring = P.accent if self._focus else HAIRLINE
        img = _shape_photo(w, h, R_CONTROL, _rgb(P.field), _rgb(ring), 255)
        if img is not None:
            if self._img_id is None:
                self._img_id = self._canvas.create_image(0, 0, anchor="nw", image=img)
                self._canvas.tag_lower(self._img_id)
            else:
                self._canvas.itemconfigure(self._img_id, image=img)
        self._canvas.itemconfigure(self._win, width=max(20, w - 24))

    def get(self) -> str:
        return self.entry.get()

    def set(self, value: str) -> None:
        state = self.entry.cget("state")
        self.entry.configure(state="normal")
        self.entry.delete(0, "end")
        self.entry.insert(0, value)
        self.entry.configure(state=state)

    def configure_state(self, state: str) -> None:
        self.entry.configure(state=state)
        self._redraw()


class ThinScrollbar(tk.Canvas):
    """A thin rounded thumb, fading in on hover. Proxies a widget's yview."""

    def __init__(self, parent, command, *, bg: str = P.card, width: int = 10):
        # height=1: a Canvas defaults to 265px tall and would drive the parent's
        # height request; sticky="ns" gives it its real size.
        super().__init__(parent, width=width, height=1, highlightthickness=0, bd=0,
                         bg=bg, takefocus=0)
        self.command = command
        self._first, self._last = 0.0, 1.0
        self._hover = False
        self._drag_offset: float | None = None
        self.bind("<Configure>", lambda e: self._redraw())
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))
        self.bind("<Button-1>", self._press)
        self.bind("<B1-Motion>", self._drag)
        self.bind("<ButtonRelease-1>", lambda e: setattr(self, "_drag_offset", None))
        self.bind("<MouseWheel>", self._wheel)

    def set(self, first, last) -> None:
        self._first, self._last = float(first), float(last)
        self._redraw()

    def _set_hover(self, on: bool) -> None:
        self._hover = on
        self._redraw()

    def _wheel(self, event) -> None:
        self.command("scroll", -1 * (event.delta // 120), "units")

    def _geometry(self) -> tuple[float, float, int]:
        h = self.winfo_height()
        thumb = max(28.0, (self._last - self._first) * h)
        y = min(self._first * h, h - thumb)
        return max(0.0, y), thumb, self.winfo_width()

    def _press(self, event) -> None:
        y, thumb, _ = self._geometry()
        if y <= event.y <= y + thumb:
            self._drag_offset = event.y - y
        else:
            span = self._last - self._first
            target = event.y / max(1, self.winfo_height()) - span / 2
            self.command("moveto", str(max(0.0, min(1.0, target))))
            self._drag_offset = thumb / 2

    def _drag(self, event) -> None:
        if self._drag_offset is None:
            return
        h = max(1, self.winfo_height())
        self.command("moveto", str(max(0.0, min(1.0, (event.y - self._drag_offset) / h))))

    def _redraw(self) -> None:
        self.delete("all")
        if self._last - self._first >= 1.0:
            return
        y, thumb, w = self._geometry()
        alpha = 110 if self._hover else 66
        tw = max(3, w - 4)
        th = max(6, int(thumb) // 3 * 3)
        img = _cached(("thumb", tw, th, alpha), lambda: self._make_thumb(tw, th, alpha))
        if img is not None:
            self.create_image(2, y, anchor="nw", image=img)

    @staticmethod
    def _make_thumb(w: int, h: int, alpha: int):
        if not _PIL or w < 3 or h < 6:
            return None
        w_s, h_s = w * _SS, h * _SS
        img = Image.new("RGBA", (w_s, h_s), (0, 0, 0, 0))
        ImageDraw.Draw(img).rounded_rectangle((0, 0, w_s - 1, h_s - 1), w_s // 2,
                                              fill=(0, 0, 0, alpha))
        return ImageTk.PhotoImage(img.resize((w, h), Image.LANCZOS))


class ProgressRail(tk.Canvas):
    """Thin eased progress rail with a filled portion."""

    def __init__(self, parent, *, bg: str = P.card, height: int = 4):
        super().__init__(parent, height=height, highlightthickness=0, bd=0, bg=bg, takefocus=0)
        self._value = 0.0
        self._shown = 0.0
        self._anim = _Animator(self, 200)
        self._items: list[int] = []
        self.bind("<Configure>", lambda e: self._draw())

    def set(self, fraction: float) -> None:
        self._value = max(0.0, min(1.0, fraction))
        start = self._shown

        def frame(u):
            self._shown = start + (self._value - start) * u
            self._draw()

        if self._value >= start:
            self._anim.run(frame)
        else:
            self._shown = self._value
            self._draw()

    def _draw(self) -> None:
        for i in self._items:
            self.delete(i)
        self._items = []
        w, h = self.winfo_width(), self.winfo_height()
        if w < 4 or h < 3:
            return
        rail = _shape_photo(w, h, h // 2, _rgb(P.track))
        if rail is not None:
            self._items.append(self.create_image(0, 0, anchor="nw", image=rail))
        fill_w = int(w * self._shown) // 4 * 4
        if fill_w >= 8:
            fill = _shape_photo(fill_w, h, h // 2, _rgb(P.brand_orange))
            if fill is not None:
                self._items.append(self.create_image(0, 0, anchor="nw", image=fill))


class Segmented(tk.Canvas):
    """Two-state exclusive control for the output mode."""

    def __init__(self, parent, options: list[str], variable: tk.BooleanVar, *,
                 bg: str = P.card, command=None):
        self._font = _font("sm")
        self._labels = [rtl(o) for o in options]
        seg_w = max(self._font.measure(t) for t in self._labels) + 40
        self._seg_w = seg_w
        w, h = seg_w * len(options), self._font.metrics("linespace") + 16
        super().__init__(parent, width=w, height=h, highlightthickness=0, bd=0, bg=bg,
                         cursor="hand2", takefocus=1)
        self.var = variable
        self.command = command
        self._sw, self._sh = w, h
        self._seg = 0 if variable.get() else 1
        self._t = float(self._seg)
        self._anim = _Animator(self, 150)

        self._rail = self.create_image(0, 0, anchor="nw")
        self._knob = self.create_image(0, 0, anchor="nw")
        self._texts = [
            self.create_text(i * seg_w + seg_w // 2, h // 2, text=label,
                             font=self._font, fill=P.text_muted)
            for i, label in enumerate(self._labels)
        ]
        self.bind("<Button-1>", self._click)
        self.bind("<Configure>", lambda e: self._paint())
        self._paint()

    def _click(self, event) -> None:
        target = 0 if event.x < self._seg_w else 1
        if target == self._seg:
            return
        self._seg = target
        self.var.set(target == 0)
        start = self._t

        def frame(u):
            self._paint(start + (target - start) * u)

        self._anim.run(frame)
        if self.command is not None:
            self.command()

    def _paint(self, t: float | None = None) -> None:
        if t is not None:
            self._t = t
        rail = _shape_photo(self._sw, self._sh, R_CONTROL, _rgb(P.track), _rgb(HAIRLINE), 255)
        if rail is not None:
            self.itemconfigure(self._rail, image=rail)
        kw, kh = self._seg_w - 8, self._sh - 8
        knob = _shape_photo(kw, kh, R_CONTROL - 2, _rgb(P.accent))
        if knob is not None:
            self.itemconfigure(self._knob, image=knob)
            self.coords(self._knob, 4 + self._t * self._seg_w, 4)
        for i, item in enumerate(self._texts):
            active = 1.0 - min(1.0, abs(self._t - i))
            self.itemconfigure(item, fill=_hex(_mix(_rgb(P.text_muted), _rgb("#FFFFFF"), active)))


# ── App ────────────────────────────────────────────────────────────
TXT_PENDING = rtl("آماده")
TXT_OK = rtl("موفق")
TXT_FAIL = rtl("خطا")


class SanitizerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        _CACHE.clear()
        self.q: queue.Queue = queue.Queue()
        self.files: dict[str, str] = {}  # path -> detected vendor
        self._hover_iid: str | None = None

        self.title("PDN Sanitizer")
        self.geometry("1240x960")
        self.minsize(1060, 920)
        self.configure(bg=P.base)
        self._install_ttk()
        _install_fonts(self)
        icon = _brand_photo(LOGO_PATH, 64, radius=16)
        if icon is not None:
            try:
                self.iconphoto(True, icon)
            except tk.TclError:
                pass

        self._build()
        self._style_titlebar()
        self.after(100, self._drain_queue)

    # ---------- ttk (only the widgets we still use) ----------

    def _install_ttk(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=P.card, fieldbackground=P.card,
                        foreground=P.text, bordercolor=P.card, borderwidth=0,
                        rowheight=34, font=FONTS["sm"], relief="flat")
        style.map("Treeview", background=[("selected", P.accent_dim)],
                  foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview.Heading", background=P.card, foreground=P.text_dim,
                        font=FONTS["xs"], relief="flat", borderwidth=0, padding=(10, 6))
        style.map("Treeview.Heading", background=[("active", P.card)])

    def _style_titlebar(self) -> None:
        """Blend the native title bar into the light base (Windows 10 2004+)."""
        if sys.platform != "win32":
            return
        try:
            import ctypes

            self.update_idletasks()
            self.update()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            # attr 20: immersive light chrome (base #F2F4F8); 35: caption COLORREF 0x00BBGGRR
            for attr, val in ((20, ctypes.c_int(0)), (19, ctypes.c_int(0)),
                              (35, ctypes.c_int(0x00F8F4F2))):
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val),
                                                           ctypes.sizeof(val))
        except Exception:  # noqa: BLE001 - cosmetic only, never fatal
            pass

    # ---------- layout ----------

    def _build(self) -> None:
        root = tk.Frame(self, bg=P.base)
        root.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)  # the files/settings row absorbs slack

        self._build_brand_rule(root)
        self._build_header(root)

        middle = tk.Frame(root, bg=P.base)
        middle.grid(row=2, column=0, sticky="nsew", padx=14)
        middle.columnconfigure(0, weight=0, minsize=420)  # settings (left)
        middle.columnconfigure(1, weight=1)               # files (right)
        middle.rowconfigure(0, weight=1)
        self._build_settings(middle)
        self._build_files(middle)

        self._build_actions(root)
        self._build_log(root)
        self._refresh_header()

    def _build_brand_rule(self, parent) -> None:
        """A 3px letterhead rule: brand blue, with the logo's orange over the
        wordmark side. The only place both brand colours meet in the chrome."""
        rule = tk.Canvas(parent, height=3, highlightthickness=0, bd=0, bg=P.accent,
                         takefocus=0)
        rule.grid(row=0, column=0, sticky="ew")
        seg = rule.create_rectangle(0, 0, 1, 3, fill=P.brand_orange, width=0)
        rule.bind("<Configure>", lambda e: rule.coords(seg, e.width - 96, 0, e.width, 3))

    def _build_header(self, parent) -> None:
        bar = tk.Frame(parent, bg=P.base)
        bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(16, 14))
        logo = _brand_photo(QR_PATH, 40, crop=LOGO_MARK_CROP, clean=True)
        if logo is not None:
            tk.Label(bar, image=logo, bg=P.base, bd=0).pack(side="right", padx=(0, 14))
        title = tk.Frame(bar, bg=P.base)
        title.pack(side="right")
        tk.Label(title, text="PDN Sanitizer", bg=P.base, fg=P.text,
                 font=(FONT_FAMILY, 16, "bold"), anchor="e").pack(anchor="e")
        tk.Label(title, text=rtl("پویش داده نوین"), bg=P.base, fg=P.text_muted,
                 font=FONTS["xs"], anchor="e").pack(anchor="e", pady=(2, 0))
        self.header_dot = tk.Canvas(bar, width=14, height=14, highlightthickness=0, bd=0,
                                    bg=P.base, takefocus=0)
        self.header_dot.pack(side="left")
        self.header_count = tk.Label(bar, text="", bg=P.base, fg=P.text_muted, font=FONTS["sm"])
        self.header_count.pack(side="left", padx=(8, 0))
        self._dot_item = self.header_dot.create_image(2, 2, anchor="nw")
        self._set_header_dot("pending")

    def _set_header_dot(self, status: str) -> None:
        img = _dot_photo(10, STATUS_COLORS.get(status, P.text_muted))
        if img is not None:
            self.header_dot.itemconfigure(self._dot_item, image=img)

    def _eyebrow(self, parent, text: str) -> None:
        """Section label. Plain small bold text; no hairline, no letter-spaced caps."""
        tk.Label(parent, text=rtl(text), bg=P.card, fg=P.text_muted,
                 font=(FONT_FAMILY, 10, "bold"), anchor="e").pack(fill="x", pady=(0, 6))

    def _build_settings(self, parent) -> None:
        island = Island(parent, pad=14)
        island.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        box = island.body

        head = tk.Frame(box, bg=P.card)
        head.pack(fill="x")
        tk.Label(head, text=rtl("تنظیمات"), bg=P.card, fg=P.text, font=FONTS["lg"],
                 anchor="e").pack(side="right")
        tk.Frame(box, bg=HAIRLINE, height=1).pack(fill="x", pady=(10, 12))

        xml = tk.Frame(box, bg=P.card)
        xml.pack(fill="x")
        self._eyebrow(xml, "XML")
        self.v_anonymise = tk.BooleanVar(value=False)
        self.v_aggressive = tk.BooleanVar(value=False)
        self.v_keep_private = tk.BooleanVar(value=True)
        self.v_url_users = tk.BooleanVar(value=False)
        for text, var in (("ناشناس‌سازی IP / دامنه / MAC", self.v_anonymise),
                          ("حذف تهاجمی متن", self.v_aggressive),
                          ("نمایان ماندن IP‌های خصوصی", self.v_keep_private),
                          ("حذف نام کاربری در URL‌ها", self.v_url_users)):
            Toggle(xml, var, text).pack(fill="x", pady=2)

        cli = tk.Frame(box, bg=P.card)
        cli.pack(fill="x", pady=(14, 0))
        self._eyebrow(cli, "CLI · FortiGate / MikroTik / Cisco")
        tk.Label(cli, text=rtl("جانشین مقادیر حساس"), bg=P.card, fg=P.text_muted,
                 font=FONTS["xs"], anchor="e").pack(fill="x", pady=(0, 5))
        self.cli_replacement = Field(cli)
        self.cli_replacement.pack(fill="x")
        self.cli_replacement.set("<REDACTED>")

        mapping = tk.Frame(box, bg=P.card)
        mapping.pack(fill="x", pady=(14, 0))
        self._eyebrow(mapping, "نگاشت")
        self.v_mapping = tk.BooleanVar(value=False)
        Toggle(mapping, self.v_mapping, "نگاشت بازگشت‌پذیر برای هر مقدار").pack(fill="x")
        tk.Label(mapping, text=rtl("هر مقدار یکسان ← همان توکن (خروجی قابل بازیابی)."),
                 bg=P.card, fg=P.text_dim, font=FONTS["xs"], anchor="e",
                 justify="right", wraplength=340).pack(fill="x", pady=(8, 0))

    def _build_files(self, parent) -> None:
        island = Island(parent, pad=14)
        island.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        box = island.body
        box.rowconfigure(2, weight=1)
        box.columnconfigure(0, weight=1)

        head = tk.Frame(box, bg=P.card)
        head.grid(row=0, column=0, sticky="ew")
        tk.Label(head, text=rtl("فایل‌های پیکربندی"), bg=P.card, fg=P.text,
                 font=FONTS["lg"]).pack(side="right")
        self.files_hint = tk.Label(head, text=rtl("برای افزودن، از دکمه‌های زیر استفاده کنید"),
                                   bg=P.card, fg=P.text_dim, font=FONTS["xs"])
        self.files_hint.pack(side="left")
        tk.Frame(box, bg=HAIRLINE, height=1).grid(row=1, column=0, sticky="ew", pady=(10, 10))

        wrap = tk.Frame(box, bg=P.card)
        wrap.grid(row=2, column=0, sticky="nsew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(wrap, columns=("file", "status"),
                                 show=("tree", "headings"), height=6)
        self.tree.heading("#0", text="")
        self.tree.heading("file", text=rtl("فایل"), anchor="e")
        self.tree.heading("status", text=rtl("وضعیت"), anchor="e")
        self.tree.column("#0", width=196, minwidth=196, stretch=False, anchor="w")
        self.tree.column("status", width=92, minwidth=80, stretch=False, anchor="e")
        self.tree.column("file", width=360, minwidth=200, stretch=True, anchor="e")
        self.tree["displaycolumns"] = ("status", "file")
        self.tree.grid(row=0, column=0, sticky="nsew")
        for tag, color in (("ok", P.ok), ("failed", P.danger),
                           ("pending", P.text_muted), ("running", P.warn)):
            self.tree.tag_configure(tag, foreground=color)
        self.tree.tag_configure("hover", background=P.card_hi)  # last: wins for background

        self.empty_hint = tk.Label(
            wrap, text=rtl("فایلی اضافه نشده است. با «افزودن فایل‌ها» شروع کنید."),
            bg=P.card, fg=P.text_dim, font=FONTS["sm"])
        self.empty_hint.place(relx=0.5, rely=0.5, anchor="center")

        self.files_scroll = ThinScrollbar(wrap, self.tree.yview)
        self.files_scroll.grid(row=0, column=1, sticky="ns", padx=(6, 0))
        self.tree.configure(yscrollcommand=self.files_scroll.set)
        self.tree.bind("<Motion>", self._hover_row)
        self.tree.bind("<Leave>", lambda e: self._hover_row(None))

        bar = tk.Frame(box, bg=P.card)
        bar.grid(row=3, column=0, sticky="ew", pady=(14, 0))
        Button(bar, "افزودن فایل‌ها", self.add_files, kind="ghost").pack(side="right")
        Button(bar, "افزودن پوشه", self.add_folder, kind="quiet").pack(side="right", padx=8)
        Button(bar, "حذف", self.remove_selected, kind="quiet").pack(side="right")
        Button(bar, "پاک‌کردن", self.clear_files, kind="quiet").pack(side="right", padx=8)

        tk.Frame(box, bg=HAIRLINE, height=1).grid(row=4, column=0, columnspan=2,
                                                  sticky="ew", pady=(14, 12))
        brand = tk.Frame(box, bg=P.card)
        brand.grid(row=5, column=0, columnspan=2, sticky="ew")
        qr = _qr_photo(76)
        if qr is not None:
            tk.Label(brand, image=qr, bg=P.card, bd=0).pack(side="left")

    def _hover_row(self, event) -> None:
        row = self.tree.identify_row(event.y) if event is not None else ""
        if row == self._hover_iid:
            return
        prev, self._hover_iid = self._hover_iid, row
        if prev and self.tree.exists(prev):
            self.tree.item(prev, tags=tuple(t for t in self.tree.item(prev, "tags") if t != "hover"))
        if row and self.tree.exists(row):
            tags = tuple(self.tree.item(row, "tags"))
            if "hover" not in tags:
                self.tree.item(row, tags=tags + ("hover",))

    def _build_actions(self, parent) -> None:
        island = Island(parent, pad=12)
        island.grid(row=3, column=0, sticky="ew", padx=14, pady=(14, 10))
        box = island.body
        box.columnconfigure(1, weight=1)

        left = tk.Frame(box, bg=P.card)
        left.grid(row=0, column=0, sticky="w")
        self.btn_sanitize = Button(left, "پاکسازی", self.sanitize_all, kind="primary")
        self.btn_sanitize.pack(side="left")
        Button(left, "بازگردانی از نگاشت…", self.restore_dialog,
               kind="ghost").pack(side="left", padx=10)

        right = tk.Frame(box, bg=P.card)
        right.grid(row=0, column=1, sticky="e")
        tk.Label(right, text=rtl("خروجی"), bg=P.card, fg=P.text_dim, font=FONTS["xs"],
                 anchor="e").pack(fill="x", pady=(0, 6))
        self.v_beside = tk.BooleanVar(value=True)
        Segmented(right, ["کنار فایل مبدأ", "پوشهٔ خروجی"], self.v_beside,
                  command=self._toggle_dir).pack(anchor="e")

        self.sub_out = tk.Frame(box, bg=P.card)
        self.sub_out.grid(row=1, column=0, columnspan=2, sticky="e", pady=(10, 0))
        self.v_outdir = tk.StringVar(value="")
        self.ent_outdir = Field(self.sub_out, textvariable=self.v_outdir, width=320)
        self.ent_outdir.pack(side="right")
        self.btn_outdir = Button(self.sub_out, "انتخاب پوشه", self.pick_outdir, kind="quiet")
        self.btn_outdir.pack(side="right", padx=(0, 10))
        self._toggle_dir()

    def _build_log(self, parent) -> None:
        island = Island(parent, pad=14)
        island.grid(row=4, column=0, sticky="nsew", padx=14, pady=(0, 14))
        box = island.body
        box.columnconfigure(0, weight=1)

        head = tk.Frame(box, bg=P.card)
        head.grid(row=0, column=0, sticky="ew")
        tk.Label(head, text=rtl("گزارش"), bg=P.card, fg=P.text, font=FONTS["lg"]).pack(side="right")
        self.log_summary = tk.Label(head, text=rtl("آماده"), bg=P.card, fg=P.text_muted,
                                    font=FONTS["xs"])
        self.log_summary.pack(side="left")

        self.progress = ProgressRail(box)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(12, 12))

        wrap = tk.Frame(box, bg=P.card)
        wrap.grid(row=2, column=0, sticky="nsew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)
        box.rowconfigure(2, weight=1)

        self.log = tk.Text(wrap, height=4, wrap="word", state="disabled", bd=0,
                           highlightthickness=0, bg=P.card, fg=P.text,
                           insertbackground=P.text, relief="flat", font=MONO,
                           selectbackground=P.accent_dim, spacing1=2, spacing3=2)
        self.log.grid(row=0, column=0, sticky="nsew")
        self.log_scroll = ThinScrollbar(wrap, self.log.yview)
        self.log_scroll.grid(row=0, column=1, sticky="ns", padx=(6, 0))
        self.log.configure(yscrollcommand=self.log_scroll.set)
        self.log.tag_configure("rtl", justify="right")
        self.log.tag_configure("muted", foreground=P.text_dim)
        self.log.tag_configure("ok", foreground=P.ok)
        self.log.tag_configure("fail", foreground=P.danger)
        self.log.tag_configure("accent", foreground=P.accent)
        self.log.tag_configure("fade", foreground=P.text_dim)  # created last: wins briefly

    # ---------- file selection ----------

    def add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="انتخاب فایل‌های پیکربندی", filetypes=FILE_TYPES)
        for p in paths:
            self._add_path(Path(p))

    def add_folder(self) -> None:
        folder = filedialog.askdirectory(title="انتخاب پوشهٔ پیکربندی‌ها")
        if not folder:
            return
        for p in sorted(Path(folder).rglob("*")):
            if p.is_file() and p.suffix.lower() in (".xml", ".conf", ".rsc", ".txt"):
                self._add_path(p)

    def _add_path(self, path: Path) -> None:
        key = str(path)
        if key in self.files:
            return
        try:
            vendor = detect_vendor(path.read_bytes())
        except OSError as exc:
            self._log(f"!  خواندن {path} ممکن نشد: {exc}", "fail")
            return
        self.files[key] = vendor
        self.tree.insert("", "end", iid=key, image=_chip_photo(vendor, "pending"),
                         values=(path.name, TXT_PENDING), tags=("pending",))
        self._refresh_header()

    def remove_selected(self) -> None:
        for iid in self.tree.selection():
            self.tree.delete(iid)
            self.files.pop(iid, None)
        self._refresh_header()

    def clear_files(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.files.clear()
        self._refresh_header()

    def _refresh_header(self) -> None:
        n = len(self.files)
        self.header_count.configure(text=rtl(f"{n} فایل") if n else rtl("بدون فایل"))
        if self.v_beside.get():
            self.files_hint.configure(
                text="" if not n else rtl(f"{n} فایل آمادهٔ پاکسازی"))
        hint = getattr(self, "empty_hint", None)
        if hint is not None:
            if n:
                hint.place_forget()
            else:
                hint.place(relx=0.5, rely=0.5, anchor="center")

    def _toggle_dir(self) -> None:
        folder = not self.v_beside.get()
        state = "normal" if folder else "disabled"
        self.ent_outdir.configure_state(state)
        self.btn_outdir.configure_state(state)
        if folder:
            self.sub_out.grid()
        else:
            self.sub_out.grid_remove()

    def restore_dialog(self) -> None:
        src = filedialog.askopenfilename(title="فایل پاکسازی‌شده برای بازگردانی")
        if not src:
            return
        mp = filedialog.askopenfilename(
            title="فایل نگاشت", filetypes=[("Mapping JSON", "*.json"), ("همهٔ فایل‌ها", "*.*")])
        if not mp:
            return
        out = filedialog.asksaveasfilename(
            title="ذخیرهٔ فایل بازگردانی‌شده", initialfile=f"restored-{Path(src).name}")
        if not out:
            return
        try:
            mapper = TokenMapper.load_json(mp)
            restored = mapper.restore(Path(src).read_text(encoding="utf-8"))
            Path(out).write_text(restored, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - report any failure to the user
            messagebox.showerror("بازگردانی ناموفق بود", str(exc))
            return
        self._log(f"بازگردانی انجام شد ({Path(src).name} + {Path(mp).name} → {out})", "accent")
        messagebox.showinfo("بازگردانی انجام شد", f"نوشته شد: {out}")

    def pick_outdir(self) -> None:
        d = filedialog.askdirectory(title="پوشهٔ خروجی")
        if d:
            self.v_outdir.set(d)

    # ---------- sanitize ----------

    def sanitize_all(self) -> None:
        if not self.files:
            messagebox.showinfo("کاری برای انجام نیست", "حداقل یک فایل پیکربندی اضافه کنید.")
            return
        if not self.v_beside.get() and not self.v_outdir.get():
            messagebox.showwarning("پوشهٔ خروجی انتخاب نشده",
                                   "یک پوشهٔ خروجی انتخاب کنید یا حالت «کنار فایل مبدأ» را برگزینید.")
            return
        # Tk variables may only be read from the main thread: snapshot them here
        # and hand the worker plain data (it never touches a Tk object).
        opts = {
            "anonymise": self.v_anonymise.get(),
            "aggressive": self.v_aggressive.get(),
            "keep_private": self.v_keep_private.get(),
            "url_users": self.v_url_users.get(),
            "replacement": self.cli_replacement.get() or "<REDACTED>",
            "beside": self.v_beside.get(),
            "outdir": self.v_outdir.get(),
            "mapper": TokenMapper() if self.v_mapping.get() else None,
        }
        self.btn_sanitize.configure_state("disabled")
        self._set_header_dot("running")
        self.progress.set(0.0)
        self.log_summary.configure(text=rtl(f"0 / {len(self.files)} فایل"))
        for iid in self.tree.get_children():
            values = list(self.tree.item(iid, "values"))
            values[1] = TXT_PENDING
            self.tree.item(iid, image=_chip_photo(self.files.get(iid, "unknown"), "running"),
                           values=values, tags=("running",))
        self._log("شروع پاکسازی", "muted")
        threading.Thread(target=self._worker, args=(list(self.files.items()), opts),
                         daemon=True).start()

    def _worker(self, items: list[tuple[str, str]], opts: dict) -> None:
        mapper = opts["mapper"]
        total = len(items)
        for index, (path, vendor) in enumerate(items, start=1):
            try:
                ok, msg = self._sanitize_one(path, vendor, opts)
            except Exception as exc:  # noqa: BLE001 - surface any engine error to the log
                ok, msg = False, f"خطا: {exc}"
            self.q.put(("row", path, vendor, "ok" if ok else "failed", msg))
            self.q.put(("progress", index, total))

        if mapper is not None and len(mapper):
            base = Path(opts["outdir"]) if (not opts["beside"] and opts["outdir"]) \
                else Path(items[0][0]).parent
            jp = base / "sanitize-mapping.json"
            mapper.save_json(jp)
            mapper.save_csv(base / "sanitize-mapping.csv")
            self.q.put(("log", f"نگاشت: {len(mapper)} مقدار متمایز ذخیره شد ({jp.name} و .csv)", "accent"))
        self.q.put(("done", None))

    def _sanitize_one(self, path: str, vendor: str, opts: dict) -> tuple[bool, str]:
        src = Path(path)
        out_name = f"sanitized-{src.name}"
        out_dir = Path(opts["outdir"]) if not opts["beside"] else src.parent
        out = out_dir / out_name

        if vendor == "unknown":
            return False, "سازنده ناشناخته — نادیده گرفته شد"

        if vendor == "opnsense":
            redactor = PfSenseRedactor(
                keep_private_ips=opts["keep_private"],
                anonymise=opts["anonymise"],
                aggressive=opts["aggressive"],
                redact_url_usernames=opts["url_users"],
                mapper=opts["mapper"],
            )
            ok = redactor.redact_config(str(src), str(out))
            return bool(ok), f"XML نوشته شد در {out.name}"

        data = src.read_bytes()
        if vendor == "fortigate":
            result = redact_fortigate_config(data, replacement=opts["replacement"],
                                             mapper=opts["mapper"])
        elif vendor == "mikrotik":
            result = redact_mikrotik_config(data, replacement=opts["replacement"],
                                            mapper=opts["mapper"])
        elif vendor == "cisco":
            result = redact_cisco_config(data, replacement=opts["replacement"],
                                         mapper=opts["mapper"])
        else:
            return False, "سازنده ناشناخته — نادیده گرفته شد"

        out.write_text(result.content, encoding="utf-8")
        return True, f"{result.redacted_values} مقدار حذف شد · {out.name}"

    # ---------- queue + log ----------

    def _drain_queue(self) -> None:
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "row":
                    _, path, vendor, status, msg = item
                    if self.tree.exists(path):
                        values = list(self.tree.item(path, "values"))
                        values[1] = TXT_OK if status == "ok" else TXT_FAIL
                        self.tree.item(path, image=_chip_photo(vendor, status),
                                       values=values, tags=(status,))
                    mark = "✓" if status == "ok" else "✗"
                    self._log(f"{mark}  {Path(path).name}  ·  {msg}",
                              "ok" if status == "ok" else "fail")
                elif kind == "progress":
                    _, done, total = item
                    self.progress.set(done / total if total else 1.0)
                    self.log_summary.configure(text=rtl(f"{done} / {total} فایل"))
                elif kind == "log":
                    self._log(item[1], item[2] if len(item) > 2 else None)
                elif kind == "done":
                    self.btn_sanitize.configure_state("normal")
                    self._set_header_dot("ok")
                    self._log("پایان", "muted")
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _log(self, text: str, tag: str | None = None) -> None:
        tags = ("rtl",) if tag is None else ("rtl", tag)
        self.log.configure(state="normal")
        start = self.log.index("end-1c")
        self.log.insert("end", rtl(text) + "\n", tags)
        # one-step fade-in: dim on insert, settle to the final colour
        self.log.tag_add("fade", start, "end-1c")
        self.log.after(130, lambda: self.log.tag_remove("fade", start, "end-1c"))
        self.log.see("end")
        self.log.configure(state="disabled")


def main() -> None:
    SanitizerApp().mainloop()


if __name__ == "__main__":
    main()
