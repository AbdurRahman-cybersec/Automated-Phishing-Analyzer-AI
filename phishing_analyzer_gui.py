#!/usr/bin/env python3
"""
URL Phishing Analyzer — Minimalist GUI
Performs deep website analysis: downloads all assets, runs JS/CSS static analysis,
offline heuristic scoring, and optional AI-powered phishing detection.
"""

import os
import json
import base64
import re
import tkinter as tk
import threading

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

# Import scraper functions
import url_scraper
from url_scraper import (
    normalize_url, get_domain, analyze_url,
    set_api_key, set_deepseek_key, set_ai_provider,
    set_virustotal_key, set_phishtank_key, set_openrouter_model,
    OPENROUTER_FREE_MODELS,
)

# Where saved API keys live (base64-obfuscated, not plaintext)
KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".api_keys")


class PhishingAnalyzerApp:
    """Minimalist GUI for the URL Phishing Analyzer."""

    # ── Theme Variables — light desktop dashboard approximation ──
    BG = "#f1f4f8"
    SHELL = "#ffffff"
    CARD_BG = "#ffffff"
    CARD_BG_ALT = "#f8fbff"
    BORDER = "#dbe4ef"
    DIVIDER = "#e6edf5"
    TEXT = "#162033"
    TEXT_SEC = "#41536b"
    TEXT_MUTED = "#76879c"
    INPUT_BG = "#f4f9ff"
    ACCENT = "#007aff"
    ACCENT_GLOW = "#c9e2ff"
    ACCENT_BG = "#eaf4ff"
    GREEN = "#10b981"
    GREEN_BG = "#e8faf3"
    RED = "#e91e63"
    RED_BG = "#fdeaf2"
    YELLOW = "#f59e0b"
    YELLOW_BG = "#fff6df"
    ORANGE = "#f59e0b"
    ORANGE_BG = "#fff2da"
    BTN_HOVER = "#dcebff"
    FOCUS = "#77b6ff"

    LIGHT_THEME = {
        "BG": "#f1f4f8",
        "SHELL": "#ffffff",
        "CARD_BG": "#ffffff",
        "CARD_BG_ALT": "#f8fbff",
        "BORDER": "#dbe4ef",
        "DIVIDER": "#e6edf5",
        "TEXT": "#162033",
        "TEXT_SEC": "#41536b",
        "TEXT_MUTED": "#76879c",
        "INPUT_BG": "#f4f9ff",
        "ACCENT": "#007aff",
        "ACCENT_GLOW": "#c9e2ff",
        "ACCENT_BG": "#eaf4ff",
        "GREEN": "#10b981",
        "GREEN_BG": "#e8faf3",
        "RED": "#e91e63",
        "RED_BG": "#fdeaf2",
        "YELLOW": "#f59e0b",
        "YELLOW_BG": "#fff6df",
        "ORANGE": "#f59e0b",
        "ORANGE_BG": "#fff2da",
        "BTN_HOVER": "#dcebff",
        "FOCUS": "#77b6ff",
    }

    DARK_THEME = {
        "BG": "#0e1420",
        "SHELL": "#151d2b",
        "CARD_BG": "#192234",
        "CARD_BG_ALT": "#111a29",
        "BORDER": "#2d3a50",
        "DIVIDER": "#263349",
        "TEXT": "#edf4ff",
        "TEXT_SEC": "#b8c7dc",
        "TEXT_MUTED": "#8191a8",
        "INPUT_BG": "#101827",
        "ACCENT": "#5aa7ff",
        "ACCENT_GLOW": "#2f6da8",
        "ACCENT_BG": "#132b46",
        "GREEN": "#34d399",
        "GREEN_BG": "#0f2d25",
        "RED": "#ff4f8b",
        "RED_BG": "#331424",
        "YELLOW": "#fbbf24",
        "YELLOW_BG": "#33280e",
        "ORANGE": "#fb923c",
        "ORANGE_BG": "#34210f",
        "BTN_HOVER": "#203756",
        "FOCUS": "#7bbcff",
    }

    def __init__(self, root):
        self.root = root
        self.dark_mode = False
        self._apply_theme()
        self.root.title("Phishing Analyzer")
        self.root.configure(bg=self.BG)
        self.root.minsize(1080, 720)

        # Center window
        win_w, win_h = 1240, 820
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - win_w) // 2
        y = max((sh - win_h) // 2, 20)
        self.root.geometry(f"{win_w}x{win_h}+{x}+{y}")

        self._setup_fonts()

        # State
        self.is_analyzing = False
        self._resize_timer = None
        self._current_result = None  # (extracted, analysis, js, css, assets)
        self._collapsed_sections = set()  # section IDs currently collapsed
        self._canvas_images = []
        self._click_regions = []

        # API key state — each key gets its own entry, var, and toggle
        self._api_section_visible = False

        self._ai_provider = tk.StringVar(value=url_scraper.AI_PROVIDER or 'openrouter')
        self._ai_model = tk.StringVar(value=url_scraper.OPENROUTER_MODEL or OPENROUTER_FREE_MODELS[0])

        self._keys = {
            'ai':          {'var': tk.StringVar(), 'placeholder': True, 'show': False,
                            'env': url_scraper.OPENROUTER_API_KEY or url_scraper.DEEPSEEK_API_KEY or '',
                            'setter': self._apply_ai_key},
            'virustotal':  {'var': tk.StringVar(), 'placeholder': True, 'show': False,
                            'env': url_scraper.VIRUSTOTAL_API_KEY or '',
                            'setter': set_virustotal_key},
            'phishtank':   {'var': tk.StringVar(), 'placeholder': True, 'show': False,
                            'env': url_scraper.PHISHTANK_API_KEY or '',
                            'setter': set_phishtank_key},
        }

        self._build_ui()
        self._load_saved_keys()

    def _apply_theme(self):
        theme = self.DARK_THEME if self.dark_mode else self.LIGHT_THEME
        for name, value in theme.items():
            setattr(self, name, value)

    # ══════════════════════════════════════════════════════════════
    #  FONTS — simple system font stack
    # ══════════════════════════════════════════════════════════════

    def _setup_fonts(self):
        self.FONT = "Segoe UI"
        self.f_title = (self.FONT, 24, "bold")
        self.f_sub = (self.FONT, 11)
        self.f_input = (self.FONT, 14)
        self.f_btn = (self.FONT, 12, "bold")
        self.f_sm_btn = (self.FONT, 10, "bold")
        self.f_verdict = (self.FONT, 28, "bold")
        self.f_heading = (self.FONT, 11, "bold")
        self.f_section = (self.FONT, 12, "bold")
        self.f_body = (self.FONT, 11)
        self.f_body_lg = (self.FONT, 12)
        self.f_tag = (self.FONT, 10)
        self.f_status = (self.FONT, 10, "bold")

    # ══════════════════════════════════════════════════════════════
    #  BUILD UI
    # ══════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── App shell / centered dashboard container ───────────
        main = tk.Frame(self.root, bg=self.BG)
        main.pack(fill="both", expand=True)

        self.content = tk.Frame(main, bg=self.BG)
        self.content.pack(fill="both", expand=True, padx=28, pady=24)

        # ── Header card ────────────────────────────────────────
        header_card = tk.Frame(
            self.content, bg=self.SHELL, highlightthickness=1, highlightbackground=self.BORDER
        )
        header_card.pack(fill="x", pady=(0, 14))

        header = tk.Frame(header_card, bg=self.SHELL)
        header.pack(fill="x", padx=22, pady=18)

        title_col = tk.Frame(header, bg=self.SHELL)
        title_col.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_col, text="Phishing Analyzer",
            font=self.f_title, fg=self.ACCENT, bg=self.SHELL
        ).pack(anchor="w")
        tk.Label(
            title_col,
            text="AI-powered phishing triage, asset analysis, and explanation.",
            font=self.f_sub, fg=self.TEXT_SEC, bg=self.SHELL
        ).pack(anchor="w", pady=(4, 0))

        header_pill = tk.Label(
            header, text="LIVE ANALYSIS", font=self.f_tag, bg=self.GREEN_BG,
            padx=12, pady=6, highlightthickness=1, highlightbackground=self.GREEN, fg=self.GREEN
        )
        header_pill.pack(side="right")

        self.theme_btn = tk.Label(
            header, text="Dark Mode" if not self.dark_mode else "Light Mode",
            font=self.f_sm_btn, fg=self.TEXT, bg=self.ACCENT_BG,
            cursor="hand2", relief="flat", bd=0, padx=12, pady=7,
            highlightthickness=1, highlightbackground=self.BORDER,
        )
        self.theme_btn.pack(side="right", padx=(0, 10))
        self.theme_btn.bind("<Button-1>", lambda e: self._toggle_theme())
        self._bind_hover_glow(
            self.theme_btn, self.ACCENT_BG, self.BTN_HOVER,
            normal_fg=self.TEXT, hover_fg=self.ACCENT,
            normal_border=self.BORDER, hover_border=self.ACCENT_GLOW,
        )

        # ── Two-pane body layout ───────────────────────────────
        body = tk.Frame(self.content, bg=self.BG)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=0, minsize=380)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left_col = tk.Frame(body, bg=self.BG)
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 16))

        right_col = tk.Frame(body, bg=self.BG)
        right_col.grid(row=0, column=1, sticky="nsew")

        # ── API Key Section ───────────────────────────────────
        self._build_api_key_section(left_col)

        # ── URL analysis card ─────────────────────────────────
        input_card = tk.Frame(
            left_col, bg=self.SHELL, highlightthickness=1, highlightbackground=self.BORDER
        )
        input_card.pack(fill="x", pady=(0, 12))

        input_frame = tk.Frame(input_card, bg=self.SHELL)
        input_frame.pack(fill="x", padx=22, pady=18)

        intro_row = tk.Frame(input_frame, bg=self.SHELL)
        intro_row.pack(fill="x", pady=(0, 12))
        tk.Label(
            intro_row, text="Analyze URL", font=self.f_section, fg=self.TEXT, bg=self.SHELL
        ).pack(side="left")
        tk.Label(
            intro_row,
            text="Paste a target URL to generate a phishing verdict, AI summary, and site report.",
            font=self.f_tag, fg=self.TEXT_MUTED, bg=self.SHELL
        ).pack(side="left", padx=(10, 0))

        # Input row: entry + button side by side
        row = tk.Frame(input_frame, bg=self.SHELL)
        row.pack(fill="x")

        # Entry shell with focus glow
        self.entry_border = tk.Frame(
            row, bg=self.INPUT_BG, bd=0, highlightthickness=1, highlightbackground=self.BORDER
        )
        self.entry_border.pack(side="left", fill="x", expand=True, ipady=6)

        self.url_var = tk.StringVar()
        self.entry = tk.Entry(
            self.entry_border, textvariable=self.url_var,
            font=self.f_input, bg=self.INPUT_BG,
            fg=self.TEXT, insertbackground=self.TEXT,
            relief="flat", bd=0, highlightthickness=0,
        )
        self.entry.pack(fill="x", expand=True, padx=16, ipady=10)

        self._placeholder_active = True
        self._set_placeholder()
        self.entry.bind("<FocusIn>", self._on_focus_in)
        self.entry.bind("<FocusOut>", self._on_focus_out)
        self.entry.bind("<Return>", lambda e: self._start_analysis())

        # Scan button with primary hierarchy / subtle glow
        self.analyze_btn = tk.Label(
            row, text="Analyze URL",
            font=self.f_btn, fg="#ffffff",
            bg=self.RED, cursor="hand2",
            relief="flat", bd=0,
            padx=26, pady=14,
            highlightthickness=1, highlightbackground="#f7b4cd",
        )
        self.analyze_btn.pack(side="left", padx=(14, 0))
        self.analyze_btn.bind("<Button-1>", lambda e: self._start_analysis())
        self._bind_hover_glow(
            self.analyze_btn, self.RED, "#ff2f7d",
            normal_fg="#ffffff", hover_fg="#ffffff",
            normal_border="#f7b4cd", hover_border=self.RED_BG,
        )

        assist_row = tk.Frame(input_frame, bg=self.SHELL)
        assist_row.pack(fill="x", pady=(12, 0))
        tk.Label(
            assist_row,
            text="Supports offline heuristics, VirusTotal/PhishTank checks, optional AI, and screenshot preview.",
            font=self.f_tag, fg=self.TEXT_MUTED, bg=self.SHELL
        ).pack(side="left")

        # ── Status / actions card ─────────────────────────────
        self.status_card = tk.Frame(
            left_col, bg=self.CARD_BG, highlightthickness=1, highlightbackground=self.BORDER
        )
        self.status_card.pack(fill="x", pady=(0, 12))

        self.status_row = tk.Frame(self.status_card, bg=self.CARD_BG)
        self.status_row.pack(fill="x", padx=18, pady=12)

        self.status_icon = tk.Label(
            self.status_row, text="●", font=(self.FONT, 12, "bold"),
            fg=self.ACCENT, bg=self.CARD_BG
        )
        self.status_icon.pack(side="left", padx=(0, 10))

        self.status_var = tk.StringVar(value="")
        self.status_label = tk.Label(
            self.status_row, textvariable=self.status_var,
            font=self.f_status, fg=self.TEXT_SEC, bg=self.CARD_BG,
            anchor="w",
        )
        self.status_label.pack(side="left", fill="x", expand=True)

        self.copy_btn = tk.Label(
            self.status_row, text="Copy All",
            font=self.f_sm_btn, fg=self.TEXT, bg=self.ACCENT_BG,
            cursor="hand2", relief="flat", bd=0,
            padx=14, pady=7,
            highlightthickness=1, highlightbackground=self.BORDER,
        )
        self.copy_btn.pack(side="right")
        self.copy_btn.bind("<Button-1>", lambda e: self._copy_all_results())
        self._bind_hover_glow(
            self.copy_btn, self.ACCENT_BG, self.BTN_HOVER,
            normal_fg=self.TEXT, hover_fg=self.ACCENT,
            normal_border=self.BORDER, hover_border=self.ACCENT_GLOW,
        )
        self.copy_btn.pack_forget()
        self._set_status_message("Ready. Enter a URL to begin analysis.", "info", "●")

        # ── Result shell / centered report area ───────────────
        result_shell = tk.Frame(
            right_col, bg=self.SHELL, highlightthickness=1, highlightbackground=self.BORDER
        )
        result_shell.pack(fill="both", expand=True)

        shell_head = tk.Frame(result_shell, bg=self.SHELL)
        shell_head.pack(fill="x", padx=18, pady=(14, 8))
        tk.Label(
            shell_head, text="Analysis Report", font=self.f_section, fg=self.TEXT, bg=self.SHELL
        ).pack(side="left")
        tk.Label(
            shell_head, text="Structured phishing verdict, AI explanation, and site intelligence.",
            font=self.f_tag, fg=self.TEXT_MUTED, bg=self.SHELL
        ).pack(side="left", padx=(10, 0))

        # ── Result canvas with scrollbar ──────────────────────
        result_wrapper = tk.Frame(result_shell, bg=self.SHELL)
        result_wrapper.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        result_wrapper.grid_rowconfigure(0, weight=1)
        result_wrapper.grid_columnconfigure(0, weight=1)

        self.result_canvas = tk.Canvas(
            result_wrapper, bg=self.SHELL, highlightthickness=0, bd=0,
        )
        self.result_canvas.grid(row=0, column=0, sticky="nsew")

        self.result_scrollbar = tk.Scrollbar(
            result_wrapper, orient="vertical",
            command=self.result_canvas.yview,
            bg=self.CARD_BG, troughcolor=self.BG,
            activebackground=self.DIVIDER,
            width=8,
        )
        self.result_scrollbar.grid(row=0, column=1, sticky="ns")
        self.result_canvas.configure(yscrollcommand=self.result_scrollbar.set)

        self.result_canvas.bind("<Configure>", self._on_result_resize)

        # Mousewheel scrolling
        def _on_mousewheel(event):
            self.result_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        self.result_canvas.bind("<MouseWheel>", _on_mousewheel)
        # Linux scroll events
        self.result_canvas.bind("<Button-4>", lambda e: self.result_canvas.yview_scroll(-1, "units"))
        self.result_canvas.bind("<Button-5>", lambda e: self.result_canvas.yview_scroll(1, "units"))
        # Also scroll when mouse is over scrollbar
        self.result_scrollbar.bind("<MouseWheel>", _on_mousewheel)
        # Click to toggle section collapse/expand
        self.result_canvas.bind("<Button-1>", self._on_canvas_click)

        self.screenshot_info_btn = tk.Canvas(
            self.root, width=44, height=44, bg=self.BG,
            highlightthickness=0, bd=0, cursor="hand2",
        )
        self.screenshot_info_btn.place(x=18, rely=1.0, y=-18, anchor="sw")
        self.screenshot_info_btn.bind("<Button-1>", lambda e: self._show_screenshot_info())
        self._draw_screenshot_info_button(self.ACCENT, self.ACCENT_GLOW)
        self.screenshot_info_btn.bind(
            "<Enter>", lambda e: self._draw_screenshot_info_button(self.RED, self.RED_BG)
        )
        self.screenshot_info_btn.bind(
            "<Leave>", lambda e: self._draw_screenshot_info_button(self.ACCENT, self.ACCENT_GLOW)
        )

    def _bind_hover_glow(self, widget, normal_bg, hover_bg,
                         normal_fg=None, hover_fg=None,
                         normal_border=None, hover_border=None):
        """Apply a brighter hover treatment to clickable label-buttons."""
        def _enter(_event):
            cfg = {"bg": hover_bg}
            if hover_fg:
                cfg["fg"] = hover_fg
            if hover_border:
                cfg["highlightbackground"] = hover_border
            widget.config(**cfg)

        def _leave(_event):
            cfg = {"bg": normal_bg}
            if normal_fg:
                cfg["fg"] = normal_fg
            if normal_border:
                cfg["highlightbackground"] = normal_border
            widget.config(**cfg)

        widget.bind("<Enter>", _enter)
        widget.bind("<Leave>", _leave)

    def _draw_screenshot_info_button(self, fill, outline):
        if not hasattr(self, 'screenshot_info_btn'):
            return
        c = self.screenshot_info_btn
        c.delete("all")
        c.configure(bg=self.BG)
        c.create_oval(3, 3, 41, 41, fill=fill, outline=outline, width=3)
        c.create_text(22, 22, text="?", font=(self.FONT, 17, "bold"),
                      fill="#ffffff", anchor="center")

    def _toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self._apply_theme()
        self.root.configure(bg=self.BG)

        current_result = self._current_result
        api_visible = self._api_section_visible
        url_text = self.url_var.get() if hasattr(self, 'url_var') else ''
        placeholder_active = getattr(self, '_placeholder_active', True)

        for child in self.root.winfo_children():
            child.destroy()

        self._api_section_visible = api_visible
        self._build_ui()

        if api_visible:
            self._api_body.pack(fill="x", padx=0, pady=(0, 8))
            self._api_chevron.config(text="▼")
        if not placeholder_active and url_text:
            self.entry.delete(0, tk.END)
            self.entry.insert(0, url_text)
            self.entry.config(fg=self.TEXT)
            self._placeholder_active = False

        self._current_result = current_result
        if current_result:
            self._display_result(*current_result)

    # ══════════════════════════════════════════════════════════════
    #  API KEY SECTION — three labeled fields, collapsible
    # ══════════════════════════════════════════════════════════════

    def _build_api_key_section(self, parent):
        # Outer card
        self._api_card = tk.Frame(parent, bg=self.SHELL, bd=0,
                                  highlightthickness=1, highlightbackground=self.BORDER)
        self._api_card.pack(fill="x", pady=(0, 12))

        # Header row — click to expand/collapse
        header = tk.Frame(self._api_card, bg=self.SHELL, cursor="hand2")
        header.pack(fill="x", padx=18, pady=(14, 10))

        def _toggle():
            self._toggle_api_section()

        header.bind("<Button-1>", lambda e: _toggle())

        self._api_chevron = tk.Label(header, text="▶", font=(self.FONT, 10),
                                     fg=self.TEXT_MUTED, bg=self.SHELL, cursor="hand2")
        self._api_chevron.pack(side="left", padx=(0, 8))
        self._api_chevron.bind("<Button-1>", lambda e: _toggle())

        self._api_header_count = tk.Label(
            header, text="", font=self.f_tag, fg=self.TEXT_MUTED,
            bg=self.SHELL, cursor="hand2")
        self._api_header_count.pack(side="right")
        self._api_header_count.bind("<Button-1>", lambda e: _toggle())

        self._api_header_label = tk.Label(
            header, text="⚙ Settings & API Keys",
            font=self.f_section, fg=self.TEXT, bg=self.SHELL, cursor="hand2")
        self._api_header_label.pack(side="left")
        self._api_header_label.bind("<Button-1>", lambda e: _toggle())

        tk.Label(
            header,
            text="Providers, models, and intel sources",
            font=self.f_tag, fg=self.TEXT_MUTED, bg=self.SHELL, cursor="hand2"
        ).pack(side="left", padx=(10, 0))

        self._refresh_api_header()

        # Body frame (hidden by default)
        self._api_body = tk.Frame(self._api_card, bg=self.SHELL)
        # Not packed initially — toggled on expand

        # Three key rows
        for key_id, meta in self._keys.items():
            self._build_key_row(self._api_body, key_id, meta)

        # Apply button at the bottom
        btn_row = tk.Frame(self._api_body, bg=self.SHELL)
        btn_row.pack(fill="x", padx=18, pady=(6, 14))

        apply_btn = tk.Label(
            btn_row, text=" Apply All Keys ",
            font=self.f_sm_btn, fg="#ffffff", bg=self.ACCENT,
            cursor="hand2", relief="flat", bd=0, padx=14, pady=5,
            highlightthickness=1, highlightbackground=self.ACCENT_GLOW,
        )
        apply_btn.pack(side="left")
        apply_btn.bind("<Button-1>", lambda e: self._apply_all_keys())
        self._bind_hover_glow(
            apply_btn, self.ACCENT, self.BTN_HOVER,
            normal_fg="#ffffff", hover_fg=self.ACCENT,
            normal_border=self.ACCENT_GLOW, hover_border=self.ACCENT_GLOW,
        )

    def _count_configured_keys(self):
        n = 0
        for key_id, meta in self._keys.items():
            if key_id == 'ai':
                has_env = bool(url_scraper.OPENROUTER_API_KEY or url_scraper.DEEPSEEK_API_KEY)
            else:
                has_env = bool(meta['env'])
            has_custom = bool(meta['var'].get().strip())
            if has_env or has_custom:
                n += 1
        return n

    def _build_key_row(self, parent, key_id, meta):
        labels = {
            'ai':         ('AI Analysis', 'DeepSeek or OpenRouter (free tiers)'),
            'virustotal': ('VirusTotal',  '70+ security engines (free tier)'),
            'phishtank':  ('PhishTank',   'Community phishing DB (free)'),
        }
        label, desc = labels[key_id]

        row = tk.Frame(parent, bg=self.CARD_BG_ALT, highlightthickness=1, highlightbackground=self.BORDER)
        row.pack(fill="x", padx=18, pady=(0, 12))

        # Label row
        label_row = tk.Frame(row, bg=self.CARD_BG_ALT)
        label_row.pack(fill="x", padx=14, pady=(12, 0))

        tk.Label(label_row, text=label, font=self.f_heading,
                 fg=self.TEXT, bg=self.CARD_BG_ALT).pack(side="left")
        tk.Label(label_row, text=desc, font=self.f_tag,
                 fg=self.TEXT_MUTED, bg=self.CARD_BG_ALT).pack(side="left", padx=(8, 0))

        # Provider dropdown for AI key
        if key_id == 'ai':
            provider_options = ['openrouter', 'deepseek']
            provider_dropdown = tk.OptionMenu(
                label_row, self._ai_provider, *provider_options,
                command=lambda _: self._on_provider_changed()
            )
            provider_dropdown.config(
                font=self.f_tag, fg="#ffffff", bg=self.ACCENT,
                activebackground=self.BTN_HOVER, activeforeground=self.TEXT,
                relief="flat", bd=0, highlightthickness=0,
            )
            provider_dropdown["menu"].config(
                font=self.f_tag, bg=self.CARD_BG_ALT, fg=self.TEXT,
                activebackground=self.BTN_HOVER, activeforeground=self.TEXT,
                relief="flat", bd=1,
            )
            provider_dropdown.pack(side="left", padx=(12, 0))

        # Model dropdown row (visible for OpenRouter)
        if key_id == 'ai':
            model_row = tk.Frame(row, bg=self.CARD_BG_ALT)
            model_row.pack(fill="x", padx=14, pady=(6, 0))

            tk.Label(model_row, text="Model:", font=self.f_tag,
                     fg=self.TEXT_MUTED, bg=self.CARD_BG_ALT).pack(side="left")

            self._model_dropdown_frame = model_row

            model_options = list(OPENROUTER_FREE_MODELS)
            # Keep display names short
            model_display = [m.split('/')[-1].replace(':free', '') for m in model_options]

            self._model_var = self._ai_model
            model_dropdown = tk.OptionMenu(
                model_row, self._model_var, *model_options,
                command=lambda _: self._on_model_changed()
            )
            model_dropdown.config(
                font=self.f_tag, fg=self.TEXT, bg=self.INPUT_BG,
                activebackground=self.BTN_HOVER, activeforeground=self.TEXT,
                relief="flat", bd=0, highlightthickness=1,
                highlightbackground=self.DIVIDER,
            )
            model_dropdown['menu'].config(
                font=self.f_tag, bg=self.CARD_BG_ALT, fg=self.TEXT,
                activebackground=self.BTN_HOVER, activeforeground=self.TEXT,
                relief="flat", bd=1,
            )
            model_dropdown.pack(side="left", padx=(6, 0))

            # Label showing fallback info
            self._model_hint = tk.Label(
                model_row, text="(tries next if fails)",
                font=self.f_tag, fg=self.TEXT_MUTED, bg=self.CARD_BG_ALT,
            )
            self._model_hint.pack(side="left", padx=(8, 0))

        # Status dot
        has_env = bool(meta['env'])
        has_custom = bool(meta['var'].get().strip() and not meta['placeholder'])
        if has_env or has_custom:
            dot_color = self.GREEN
            dot_text = "✓"
        else:
            dot_color = self.TEXT_MUTED
            dot_text = "—"

        status_dot = tk.Label(label_row, text=dot_text, font=(self.FONT, 11, "bold"),
                              fg=dot_color, bg=self.CARD_BG_ALT)
        status_dot.pack(side="right")

        # Input row
        input_row = tk.Frame(row, bg=self.CARD_BG_ALT)
        input_row.pack(fill="x", padx=14, pady=(6, 12))

        border = tk.Frame(input_row, bg=self.BORDER,
                          highlightthickness=1, highlightbackground=self.DIVIDER)
        border.pack(side="left", fill="x", expand=True, ipady=2)

        entry = tk.Entry(
            border, textvariable=meta['var'],
            font=(self.FONT, 11), bg=self.INPUT_BG,
            fg=self.TEXT, insertbackground=self.TEXT,
            relief="flat", bd=0, highlightthickness=0,
            show="●",
        )
        entry.pack(side="left", fill="x", expand=True, padx=(10, 6), ipady=3)

        # Eye toggle
        eye = tk.Label(
            border, text="👁", font=(self.FONT, 11),
            fg=self.TEXT_MUTED, bg=self.INPUT_BG, cursor="hand2",
        )
        eye.pack(side="right", padx=(0, 8))

        # Delete / clear button
        del_btn = tk.Label(
            border, text="✕", font=(self.FONT, 11, "bold"),
            fg=self.TEXT_MUTED, bg=self.INPUT_BG, cursor="hand2",
        )
        del_btn.pack(side="right", padx=(0, 4))

        def _make_delete(kid):
            def handler(event):
                self._delete_saved_key(kid)
            return handler

        del_btn.bind("<Button-1>", _make_delete(key_id))
        del_btn.bind("<Enter>", lambda e, b=del_btn: b.config(fg=self.RED))
        del_btn.bind("<Leave>", lambda e, b=del_btn: b.config(fg=self.TEXT_MUTED))

        # Store references
        meta['entry'] = entry
        meta['eye'] = eye
        meta['del_btn'] = del_btn
        meta['status_dot'] = status_dot
        if key_id == 'ai':
            provider_label = self._ai_provider.get().title()
            meta['ph_text'] = f"Paste {provider_label} API key…"
        else:
            meta['ph_text'] = f"Paste {label} API key…"

        # Placeholder behavior
        current_val = meta['var'].get().strip()
        if current_val:
            entry.config(show="●", fg=self.TEXT)
            meta['placeholder'] = False
        else:
            entry.config(show="", fg=self.TEXT_MUTED)
            entry.insert(0, meta['ph_text'])
            meta['placeholder'] = True

        # Use default-arg capture to avoid late-binding closure bug
        def _make_focus_in(m, e):
            def handler(event, meta=m, ent=e):
                self._key_focus_in(meta, ent)
            return handler

        def _make_focus_out(m, e, pt):
            def handler(event, meta=m, ent=e, ph=pt):
                self._key_focus_out(meta, ent, ph)
            return handler

        def _make_toggle(m, e):
            def handler(event, meta=m, ent=e):
                self._toggle_one_key(meta, ent)
            return handler

        entry.bind("<FocusIn>", _make_focus_in(meta, entry))
        entry.bind("<FocusOut>", _make_focus_out(meta, entry, meta['ph_text']))
        eye.bind("<Button-1>", _make_toggle(meta, entry))

    # ── Key visibility / focus helpers ─────────────────────────

    def _key_focus_in(self, meta, entry):
        if meta['placeholder']:
            entry.delete(0, tk.END)
            entry.config(fg=self.TEXT, show="●")
            meta['placeholder'] = False

    def _key_focus_out(self, meta, entry, ph_text):
        if not meta['var'].get().strip():
            entry.config(show="", fg=self.TEXT_MUTED)
            entry.delete(0, tk.END)
            entry.insert(0, ph_text)
            meta['placeholder'] = True

    def _toggle_one_key(self, meta, entry):
        if meta['placeholder']:
            return
        meta['show'] = not meta['show']
        entry.config(show="" if meta['show'] else "●")
        meta['eye'].config(fg=self.ACCENT if meta['show'] else self.TEXT_MUTED)

    def _refresh_api_header(self):
        counts = self._count_configured_keys()
        self._api_header_count.config(text=f"{counts} of 3 configured")

    def _toggle_api_section(self):
        self._api_section_visible = not self._api_section_visible
        if self._api_section_visible:
            # Pack body below header — find header and pack after it
            self._api_body.pack(fill="x", padx=0, pady=(0, 8))
            self._api_chevron.config(text="▼")
        else:
            self._api_body.pack_forget()
            self._api_chevron.config(text="▶")

    def _apply_all_keys(self):
        """Read all three entry fields and push to url_scraper."""
        # Apply AI provider and model first
        provider = self._ai_provider.get()
        set_ai_provider(provider)
        if provider == 'openrouter':
            set_openrouter_model(self._ai_model.get())

        applied = []
        for key_id, meta in self._keys.items():
            val = meta['var'].get().strip()
            if meta['placeholder'] or not val:
                val = ''
            if key_id == 'ai':
                self._apply_ai_key(val)
            else:
                meta['setter'](val)
            if val:
                provider_tag = f" ({self._ai_provider.get().title()})" if key_id == 'ai' else ''
                applied.append(key_id.title() + provider_tag)

        # Update status dots
        for key_id, meta in self._keys.items():
            if key_id == 'ai':
                has_env = bool(url_scraper.OPENROUTER_API_KEY or url_scraper.DEEPSEEK_API_KEY)
            else:
                has_env = bool(meta['env'])
            has_custom = bool(meta['var'].get().strip() and not meta['placeholder'])
            active = has_env or has_custom
            meta['status_dot'].config(
                text="✓" if active else "—",
                fg=self.GREEN if active else self.TEXT_MUTED,
            )

        self._refresh_api_header()
        self._save_keys_to_disk()

        if applied:
            model_info = f" [{self._ai_model.get().split('/')[-1]}]" if provider == 'openrouter' else ''
            names = ", ".join(applied)
            self._set_status_message(f"API keys applied: {names}{model_info}", "info", "●")
        else:
            self._set_status_message("No API keys entered — using .env if available", "warning", "!")

    def _apply_ai_key(self, key_val: str):
        """Route AI key to the correct provider based on dropdown selection."""
        if not key_val:
            set_api_key('')
            set_deepseek_key('')
            return
        provider = self._ai_provider.get()
        if provider == 'deepseek':
            set_deepseek_key(key_val)
        else:
            set_api_key(key_val)

    def _on_provider_changed(self):
        """Update placeholder, key entry, and model dropdown visibility."""
        meta = self._keys['ai']
        provider = self._ai_provider.get()
        provider_label = provider.title()
        new_ph = f"Paste {provider_label} API key…"
        meta['ph_text'] = new_ph
        if meta['placeholder']:
            meta['var'].set('')
            entry = meta.get('entry')
            if entry:
                entry.delete(0, tk.END)
                entry.insert(0, new_ph)

        # Show/hide model dropdown based on provider
        if hasattr(self, '_model_dropdown_frame'):
            if provider == 'openrouter':
                self._model_dropdown_frame.pack(fill="x", pady=(6, 0))
            else:
                self._model_dropdown_frame.pack_forget()

    def _on_model_changed(self):
        """When model dropdown changes, push to scraper immediately."""
        model = self._ai_model.get()
        if model:
            set_openrouter_model(model)

    # ══════════════════════════════════════════════════════════════
    #  PERSISTENT KEY STORAGE (base64-obfuscated)
    # ══════════════════════════════════════════════════════════════

    def _load_saved_keys(self):
        """Load keys from disk, decode, and fill the entry fields + push to scraper."""
        if not os.path.exists(KEYS_FILE):
            return

        try:
            with open(KEYS_FILE, 'r') as f:
                saved = json.load(f)
        except Exception:
            return

        # Restore provider
        provider = saved.get('_provider', 'openrouter')
        self._ai_provider.set(provider)
        set_ai_provider(provider)

        # Restore model
        model = saved.get('_model', OPENROUTER_FREE_MODELS[0])
        self._ai_model.set(model)
        set_openrouter_model(model)

        # Hide model dropdown if provider is deepseek
        if provider == 'deepseek' and hasattr(self, '_model_dropdown_frame'):
            self._model_dropdown_frame.pack_forget()

        mapping = {
            'ai':          ('ai_key',          self._apply_ai_key),
            'virustotal':  ('virustotal_key',  set_virustotal_key),
            'phishtank':   ('phishtank_key',   set_phishtank_key),
        }

        for key_id, (file_key, setter) in mapping.items():
            encoded = saved.get(file_key, '')
            if not encoded:
                continue
            try:
                decoded = base64.b64decode(encoded).decode('utf-8')
            except Exception:
                continue

            meta = self._keys[key_id]
            # Push to scraper
            setter(decoded)
            # Fill the entry (hidden state)
            meta['var'].set(decoded)
            meta['placeholder'] = False
            entry = meta.get('entry')
            if entry:
                entry.delete(0, tk.END)
                entry.insert(0, decoded)
                entry.config(show="●", fg=self.TEXT)
            # Update status dot
            meta['status_dot'].config(text="✓", fg=self.GREEN)

        self._refresh_api_header()

    def _save_keys_to_disk(self):
        """Base64-encode all entered keys and write to disk."""
        saved = {
            '_provider': self._ai_provider.get(),
            '_model':    self._ai_model.get(),
        }
        mapping = {
            'ai':          'ai_key',
            'virustotal':  'virustotal_key',
            'phishtank':   'phishtank_key',
        }
        for key_id, file_key in mapping.items():
            meta = self._keys[key_id]
            val = meta['var'].get().strip()
            if not val or meta.get('placeholder'):
                val = ''
            if val:
                encoded = base64.b64encode(val.encode('utf-8')).decode('ascii')
            else:
                encoded = ''
            saved[file_key] = encoded

        try:
            with open(KEYS_FILE, 'w') as f:
                json.dump(saved, f)
            # Make it hidden-ish on Linux/Mac
            os.chmod(KEYS_FILE, 0o600)
        except Exception:
            pass  # silently ignore disk errors

    def _delete_saved_key(self, key_id):
        """Clear one key from disk, the entry field, the scraper, and the UI dot."""
        meta = self._keys[key_id]
        meta['var'].set('')
        meta['placeholder'] = True
        entry = meta.get('entry')
        if entry:
            entry.delete(0, tk.END)
            entry.insert(0, meta['ph_text'])
            entry.config(show="", fg=self.TEXT_MUTED)

        # Clear from scraper
        if key_id == 'ai':
            self._apply_ai_key('')
        else:
            meta['setter']('')

        # Update dot
        meta['status_dot'].config(text="—", fg=self.TEXT_MUTED)

        # Persist the removal
        self._save_keys_to_disk()
        self._refresh_api_header()

    # ══════════════════════════════════════════════════════════════
    #  INPUT HELPERS
    # ══════════════════════════════════════════════════════════════

    def _set_placeholder(self):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, "Enter URL to analyze…")
        self.entry.config(fg=self.TEXT_MUTED)
        self._placeholder_active = True

    def _on_focus_in(self, event):
        self.entry_border.config(highlightbackground=self.FOCUS)
        if self._placeholder_active:
            self.entry.delete(0, tk.END)
            self.entry.config(fg=self.TEXT)
            self._placeholder_active = False

    def _on_focus_out(self, event):
        self.entry_border.config(highlightbackground=self.BORDER)
        if not self.url_var.get().strip():
            self._set_placeholder()

    def _set_status_style(self, level="info"):
        palette = {
            "info": (self.CARD_BG, self.BORDER, self.ACCENT, self.TEXT_SEC),
            "success": (self.GREEN_BG, self.GREEN, self.GREEN, self.TEXT),
            "warning": (self.YELLOW_BG, self.YELLOW, self.YELLOW, self.TEXT),
            "error": (self.RED_BG, self.RED, self.RED, self.TEXT),
        }
        bg, border, icon, text = palette.get(level, palette["info"])
        self.status_card.config(bg=bg, highlightbackground=border)
        self.status_row.config(bg=bg)
        self.status_icon.config(bg=bg, fg=icon)
        self.status_label.config(bg=bg, fg=text)

    def _set_status_message(self, text, level="info", icon=None):
        self._set_status_style(level)
        icon_map = {"info": "●", "success": "✓", "warning": "!", "error": "✕"}
        self.status_icon.config(text=icon or icon_map.get(level, "●"))
        self.status_var.set(text)

    def _set_analyze_button_state(self, busy):
        if busy:
            self.analyze_btn.config(
                bg="#f6bdd2",
                highlightbackground="#f09bbd",
                text="Analyzing...",
                fg=self.TEXT,
            )
        else:
            self.analyze_btn.config(
                bg=self.RED,
                highlightbackground="#f7b4cd",
                text="Analyze URL",
                fg="#ffffff",
            )

    # ══════════════════════════════════════════════════════════════
    #  RESIZE HANDLING
    # ══════════════════════════════════════════════════════════════

    def _on_result_resize(self, event):
        if self._resize_timer:
            self.root.after_cancel(self._resize_timer)
        self._resize_timer = self.root.after(150, self._redraw_result)

    def _redraw_result(self):
        if self._current_result:
            self._display_result(*self._current_result)

    # ══════════════════════════════════════════════════════════════
    #  ANALYSIS PIPELINE
    # ══════════════════════════════════════════════════════════════

    def _start_analysis(self):
        if self.is_analyzing:
            return

        url = self.url_var.get().strip()
        if not url or self._placeholder_active:
            self._set_status_message("Please enter a URL to analyze", "warning", "!")
            return

        self.is_analyzing = True
        self.result_canvas.delete("all")
        self._current_result = None
        self._set_status_message("Downloading page and preparing analysis…", "info", "●")
        self._set_analyze_button_state(True)

        # Auto-apply any keys entered in the GUI before analysis
        self._apply_all_keys()

        thread = threading.Thread(target=self._run_analysis, args=(url,),
                                  daemon=True)
        thread.start()

    def _run_analysis(self, url):
        try:
            result = analyze_url(url, progress_callback=self._update_status)
            self.root.after(0, lambda: self._on_analysis_complete(*result))
        except Exception as e:
            self._show_error(f"Error: {str(e)}")

    def _update_status(self, text):
        self.root.after(0, lambda: self._set_status_message(text, "info", "●"))

    def _show_error(self, msg):
        def _do():
            self._set_status_message(msg, "error", "✕")
            self.is_analyzing = False
            self._set_analyze_button_state(False)
        self.root.after(0, _do)

    def _on_analysis_complete(self, extracted, analysis, js_analyses, css_analyses, asset_results):
        self.is_analyzing = False
        self._set_analyze_button_state(False)

        domain = extracted.get('domain', 'unknown')
        source = analysis.get('source', '') if analysis else ''
        src_note = f" • {source}" if source else ""
        self._set_status_message(
            f"Analysis complete • saved to scraped_sites/{domain}/{src_note}",
            "success",
            "✓",
        )

        self._current_result = (extracted, analysis, js_analyses, css_analyses, asset_results)
        self._display_result(extracted, analysis, js_analyses, css_analyses, asset_results)

    # ══════════════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════════════
    #  RESULT DISPLAY — sections with collapse/expand
    # ══════════════════════════════════════════════════════════════

    def _toggle_section(self, section_id):
        """Collapse or expand a section by its ID."""
        if section_id in self._collapsed_sections:
            self._collapsed_sections.discard(section_id)
        else:
            self._collapsed_sections.add(section_id)
        self._redraw_result()

    def _on_canvas_click(self, event):
        """Check if a section header was clicked and toggle it."""
        cx = self.result_canvas.canvasx(event.x)
        cy = self.result_canvas.canvasy(event.y)
        for region in self._click_regions:
            x0, y0, x1, y1 = region['bbox']
            if x0 <= cx <= x1 and y0 <= cy <= y1:
                region['callback']()
                return

        for sec in self._section_headers:
            if sec['y0'] <= cy <= sec['y1']:
                self._toggle_section(sec['id'])
                return

    def _show_screenshot_info(self):
        popup = tk.Toplevel(self.root)
        popup.title("Screenshot Capture")
        popup.configure(bg=self.SHELL)
        popup.transient(self.root)
        popup.geometry("760x680")
        popup.minsize(640, 520)

        shell = tk.Frame(popup, bg=self.SHELL, highlightthickness=1, highlightbackground=self.BORDER)
        shell.pack(fill="both", expand=True, padx=18, pady=18)
        shell.grid_rowconfigure(1, weight=1)
        shell.grid_columnconfigure(0, weight=1)

        tk.Label(shell, text="Screenshot Capture Safety",
                 font=(self.FONT, 18, "bold"), fg=self.TEXT, bg=self.SHELL).grid(
            row=0, column=0, sticky="w", padx=18, pady=(16, 10)
        )

        canvas = tk.Canvas(shell, bg=self.SHELL, highlightthickness=0, bd=0)
        scroll = tk.Scrollbar(shell, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=self.SHELL)
        body_id = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.grid(row=1, column=0, sticky="nsew", padx=(18, 6))
        scroll.grid(row=1, column=1, sticky="ns", padx=(0, 12))

        def _resize_body(event):
            canvas.itemconfigure(body_id, width=event.width)
        canvas.bind("<Configure>", _resize_body)
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        def paragraph(title, text):
            tk.Label(body, text=title, font=self.f_heading, fg=self.TEXT,
                     bg=self.SHELL).pack(anchor="w", pady=(8, 3))
            tk.Label(body, text=text, font=self.f_body, fg=self.TEXT_SEC,
                     bg=self.SHELL, justify="left", wraplength=660).pack(anchor="w", fill="x")

        paragraph(
            "What happens",
            "The app launches local Chrome/Chromium through Puppeteer, opens the URL in a temporary "
            "browser profile, waits for the page to load, saves page_preview.png, and closes the browser.",
        )
        paragraph(
            "What is isolated",
            "It does not use your normal Chrome profile, saved passwords, extensions, cookies, or logged-in sessions. "
            "Each capture gets a temporary browser profile.",
        )
        paragraph(
            "What is not isolated",
            "This is not a malware sandbox. The browser process still runs on the host machine. Browser sandboxing "
            "reduces risk, but hostile browser exploits or network-based attacks should still be treated seriously.",
        )
        paragraph(
            "Recommendation",
            "Always run suspicious URL analysis in a disposable VM when possible. For unknown or high-risk phishing URLs, "
            "avoid running captures directly on your daily-use machine.",
        )

        tk.Label(body, text="Relative Safety", font=self.f_heading,
                 fg=self.TEXT, bg=self.SHELL).pack(anchor="w", pady=(16, 8))

        def safety_row(name, pct, note, color):
            row = tk.Frame(body, bg=self.CARD_BG_ALT, highlightthickness=1, highlightbackground=self.BORDER)
            row.pack(fill="x", pady=(0, 10))
            top = tk.Frame(row, bg=self.CARD_BG_ALT)
            top.pack(fill="x", padx=12, pady=(10, 4))
            tk.Label(top, text=name, font=self.f_body, fg=self.TEXT,
                     bg=self.CARD_BG_ALT).pack(side="left")
            tk.Label(top, text=f"{pct}% safer", font=self.f_tag, fg=color,
                     bg=self.CARD_BG_ALT).pack(side="right")
            bar = tk.Canvas(row, height=14, bg=self.CARD_BG_ALT, highlightthickness=0, bd=0)
            bar.pack(fill="x", padx=12, pady=(0, 6))
            bar.bind("<Configure>", lambda e, p=pct, c=color, b=bar: (
                b.delete("all"),
                b.create_rectangle(0, 2, e.width, 12, fill=self.INPUT_BG, outline=self.DIVIDER),
                b.create_rectangle(0, 2, max(6, int(e.width * p / 100)), 12, fill=c, outline="")
            ))
            tk.Label(row, text=note, font=self.f_tag, fg=self.TEXT_MUTED,
                     bg=self.CARD_BG_ALT, justify="left", wraplength=640).pack(
                anchor="w", padx=12, pady=(0, 10)
            )

        safety_row("Main machine", 35, "Convenient, but the page loads on your host. Lowest isolation.", self.RED)
        safety_row("Docker container", 55, "Useful for packaging and limiting filesystem exposure, but GUI/browser sandboxing still needs careful setup.", self.YELLOW)
        safety_row("Live Kali USB", 75, "Good temporary environment. Rebooting can discard state if persistence is disabled.", self.ACCENT)
        safety_row("Disposable VM", 90, "Best practical option. Snapshot before analysis, run the tool inside the VM, then revert snapshot.", self.GREEN)

        paragraph(
            "Docker usage",
            "A Docker setup should run the analyzer inside the container with no host home-directory mounts, a temporary output volume, "
            "and a browser installed in the image. For GUI use, forward X11/Wayland carefully or run a web/VNC desktop inside the container. "
            "Do not mount sensitive folders such as ~/.ssh, browser profiles, password stores, or Documents.",
        )
        paragraph(
            "Live Kali USB usage",
            "Boot Kali from USB, keep persistence disabled for risky testing, connect to an isolated network if possible, install dependencies, "
            "run the analyzer, then reboot to clear the session. Store reports only if you intentionally mount external storage.",
        )

        close_btn = tk.Label(shell, text="Close", font=self.f_sm_btn, fg="#ffffff", bg=self.ACCENT,
                             cursor="hand2", padx=18, pady=8, highlightthickness=1,
                             highlightbackground=self.ACCENT_GLOW)
        close_btn.grid(row=2, column=0, columnspan=2, sticky="e", padx=18, pady=(12, 16))
        close_btn.bind("<Button-1>", lambda e: popup.destroy())
        self._bind_hover_glow(
            close_btn, self.ACCENT, self.BTN_HOVER,
            normal_fg="#ffffff", hover_fg=self.ACCENT,
            normal_border=self.ACCENT_GLOW, hover_border=self.ACCENT_GLOW,
        )

    def _open_preview_zoom(self, image_path):
        if not image_path or not os.path.exists(image_path):
            self._set_status_message("Preview image is not available on disk.", "warning", "!")
            return

        popup = tk.Toplevel(self.root)
        popup.title("Website Preview")
        popup.configure(bg=self.SHELL)
        popup.geometry("1100x760")
        popup.minsize(720, 480)

        toolbar = tk.Frame(popup, bg=self.SHELL)
        toolbar.pack(fill="x", padx=14, pady=(12, 8))
        tk.Label(
            toolbar, text="Website Preview", font=self.f_section,
            fg=self.TEXT, bg=self.SHELL
        ).pack(side="left")

        viewer = tk.Frame(popup, bg=self.SHELL)
        viewer.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        viewer.grid_rowconfigure(0, weight=1)
        viewer.grid_columnconfigure(0, weight=1)

        canvas = tk.Canvas(viewer, bg=self.CARD_BG_ALT, highlightthickness=1,
                           highlightbackground=self.BORDER, xscrollincrement=20,
                           yscrollincrement=20)
        canvas.grid(row=0, column=0, sticky="nsew")
        v_scroll = tk.Scrollbar(viewer, orient="vertical", command=canvas.yview)
        h_scroll = tk.Scrollbar(viewer, orient="horizontal", command=canvas.xview)
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        canvas.configure(xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)

        state = {'zoom': 1.0, 'photo': None, 'image_id': None, 'source': None, 'initialized': False}
        if Image and ImageTk:
            state['source'] = Image.open(image_path)

        def render():
            canvas.delete("all")
            if Image and ImageTk:
                source = state['source']
                fit_scale = min(
                    max(canvas.winfo_width() - 24, 200) / source.width,
                    max(canvas.winfo_height() - 24, 200) / source.height,
                    1.0,
                )
                if not state['initialized']:
                    state['zoom'] = fit_scale
                    state['initialized'] = True
                scale = state['zoom']
                new_size = (
                    max(1, int(source.width * scale)),
                    max(1, int(source.height * scale)),
                )
                resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.BICUBIC)
                resized = source.resize(new_size, resample)
                state['photo'] = ImageTk.PhotoImage(resized)
            else:
                state['photo'] = tk.PhotoImage(file=image_path)

            state['image_id'] = canvas.create_image(
                12,
                12,
                image=state['photo'],
                anchor="nw",
            )
            bbox = canvas.bbox("all") or (0, 0, 1, 1)
            canvas.config(scrollregion=(0, 0, bbox[2] + 12, bbox[3] + 12))

        def zoom(delta):
            old_x = canvas.xview()[0]
            old_y = canvas.yview()[0]
            state['zoom'] = max(0.35, min(4.0, state['zoom'] + delta))
            render()
            canvas.xview_moveto(old_x)
            canvas.yview_moveto(old_y)

        def reset_zoom():
            if Image and ImageTk and state.get('source'):
                source = state['source']
                state['zoom'] = min(
                    max(canvas.winfo_width() - 24, 200) / source.width,
                    max(canvas.winfo_height() - 24, 200) / source.height,
                    1.0,
                )
            else:
                state['zoom'] = 1.0
            render()
            canvas.xview_moveto(0)
            canvas.yview_moveto(0)

        def _wheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        for label, delta in (("Zoom Out", -0.15), ("Reset", 0), ("Zoom In", 0.25)):
            btn = tk.Label(
                toolbar, text=label, font=self.f_sm_btn, fg=self.TEXT,
                bg=self.ACCENT_BG, cursor="hand2", padx=12, pady=7,
                highlightthickness=1, highlightbackground=self.BORDER,
            )
            btn.pack(side="right", padx=(8, 0))
            if label == "Reset":
                btn.bind("<Button-1>", lambda e: reset_zoom())
            else:
                btn.bind("<Button-1>", lambda e, d=delta: zoom(d))
            self._bind_hover_glow(
                btn, self.ACCENT_BG, self.BTN_HOVER,
                normal_fg=self.TEXT, hover_fg=self.ACCENT,
                normal_border=self.BORDER, hover_border=self.ACCENT_GLOW,
            )

        canvas.bind("<Configure>", lambda e: render())
        canvas.bind("<MouseWheel>", _wheel)
        canvas.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
        popup.after(80, render)

    def _copy_all_results(self):
        """Build a text summary of all results and copy to clipboard."""
        if not self._current_result:
            return

        extracted, analysis, js_analyses, css_analyses, asset_results = self._current_result
        lines = []

        # Verdict
        verdict = analysis.get('verdict', 'SAFE') if analysis else 'SAFE'
        risk = analysis.get('risk_score', '?') if analysis else '?'
        conf = analysis.get('confidence', '?') if analysis else '?'
        source = analysis.get('source', '') if analysis else ''

        lines.append("══════ PHISHING ANALYSIS RESULTS ══════")
        lines.append(f"URL:       {extracted.get('url', '?')}")
        lines.append(f"Domain:    {extracted.get('domain', '?')}")
        lines.append(f"Verdict:   {verdict}")
        lines.append(f"Risk:      {risk}/100")
        lines.append(f"Confidence: {conf}%")
        if source:
            lines.append(f"Source:    {source}")
        lines.append("")

        # Site Info
        lines.append("── Site Information ──")
        lines.append(f"Title:     {extracted.get('title', '?')[:100]}")
        lines.append(f"HTTP:      {extracted.get('http_status', '?')}")
        ssl = extracted.get('ssl', {})
        lines.append(f"SSL:       {'Valid' if ssl.get('valid') else 'Invalid'}  ({ssl.get('issuer', '?')})")
        lines.append(f"HTML Size: {extracted.get('html_length', 0):,} chars")
        lines.append(f"Forms:     {len(extracted.get('forms', []))}")
        lines.append(f"Login:     {'Yes' if extracted.get('has_login_form') else 'No'}")
        lines.append(f"Links:     {len(extracted.get('external_links', []))}")
        lines.append(f"Iframes:   {len(extracted.get('iframes', []))}")
        if extracted.get('meta_description'):
            lines.append(f"Desc:      {extracted['meta_description'][:120]}")
        lines.append("")

        # Intel
        whois = extracted.get('_whois', {})
        ct = extracted.get('_cert_transparency', {})
        redir = extracted.get('_redirect_chain', {})
        vt = extracted.get('_virustotal', {})
        pt = extracted.get('_phishtank', {})
        rep = extracted.get('_reputation', {})
        fav = extracted.get('_favicon', {})
        vm = extracted.get('_vm_detection', {})
        api_status = extracted.get('_api_status', {})

        if any([whois, ct, redir, vt, pt, rep, fav]):
            lines.append("── Threat Intelligence ──")
        if whois.get('age_days') is not None:
            lines.append(f"WHOIS:     {whois['age_days']} days old, registrar: {whois.get('registrar','?')}")
        if ct.get('total_certs') is not None:
            lines.append(f"Cert Trans: {ct['total_certs']} certs found")
        if redir.get('hop_count', 0) > 0:
            lines.append(f"Redirects: {redir['hop_count']} hops")
            lines.append(f"Final URL: {redir.get('final_url', '?')}")
        else:
            lines.append("Redirects: No HTTP redirects observed")
        vt_pos = vt.get('positives')
        if vt_pos is not None:
            lines.append(f"VirusTotal: {vt_pos}/{vt.get('total','?')} flagged")
        if pt.get('in_database'):
            lines.append(f"PhishTank: {'verified' if pt.get('verified') else 'reported'} phishing")
        scans = rep.get('scan_count', 0) or 0
        if scans > 0:
            lines.append(f"Reputation: {scans} scans, avg risk {rep.get('avg_risk',0):.0f}%")
        if fav.get('suspicious'):
            lines.append(f"Favicon: SUSPICIOUS — {', '.join(fav.get('reasons', []))}")
        if vm:
            lines.append(f"VM/Sandbox detection: {vm.get('summary', 'unknown')}")
        lines.append("")

        if api_status:
            lines.append("── API Status ──")
            for item in api_status.values():
                lines.append(
                    f"{item.get('name', '?')}: {item.get('status', '?').upper()} "
                    f"({item.get('provider', '?')}) — {item.get('detail', '')}"
                )
            lines.append("")

        # Assets
        if asset_results:
            js_ok = len(asset_results['js']['downloaded'])
            css_ok = len(asset_results['css']['downloaded'])
            img_ok = len(asset_results['img']['downloaded'])
            lines.append("── Downloaded Assets ──")
            lines.append(f"JS: {js_ok}  |  CSS: {css_ok}  |  Images: {img_ok}")
            lines.append("")

        # AI Explanation
        if analysis:
            ai_raw = analysis.get('ai_explanation', '')
            if ai_raw:
                lines.append("── AI Analysis ──")
                lines.append(ai_raw)
                lines.append("")

        # JS Analysis
        if js_analyses:
            flagged = [a for a in js_analyses if a.get('findings')]
            lines.append(f"── JavaScript Analysis ({len(flagged)} flagged of {len(js_analyses)}) ──")
            for a in flagged:
                lines.append(f"  {a.get('filename','?')} — score {a['score']} [{a.get('suspicion_level','?')}]")
                for f in a.get('findings', []):
                    lines.append(f"    · {f['type']}: {f['match']}")
            lines.append("")

        # CSS Analysis
        if css_analyses:
            flagged = [a for a in css_analyses if a.get('findings')]
            lines.append(f"── CSS Analysis ({len(flagged)} flagged of {len(css_analyses)}) ──")
            for a in flagged:
                lines.append(f"  {a.get('filename','?')} — score {a['score']} [{a.get('suspicion_level','?')}]")
                for f in a.get('findings', []):
                    lines.append(f"    · {f['type']}: {f['match']}")
            lines.append("")

        # Reasons
        reasons = analysis.get('reasons', []) if analysis else []
        if reasons:
            lines.append(f"── Findings Summary ({len(reasons)} reasons) ──")
            for r in reasons:
                lines.append(f"  • {r}")
            lines.append("")

        lines.append("══════════════════════════════════════")
        text = "\n".join(lines)

        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._set_status_message("Results copied to clipboard", "success", "✓")
        except Exception:
            self._set_status_message("Could not copy results to clipboard", "error", "✕")

    def _simple_explanation(self, verdict, risk_score, reasons, source, ai_explanation=None):
        """Return a 2-3 sentence plain-language explanation of the verdict.
        Uses the AI's own explanation if available, otherwise generates one locally."""
        # Use AI's explanation if it provided one in the JSON
        if ai_explanation and len(ai_explanation) > 10:
            return ai_explanation

        if verdict == 'PHISHING':
            base = (
                "This site appears to be a phishing page designed to steal credentials "
                "or personal information. It mimics a legitimate site through deceptive "
                "design and contains multiple high-risk indicators."
            )
        elif verdict == 'SUSPICIOUS':
            base = (
                "This site shows several warning signs but doesn't conclusively appear "
                "to be a phishing page. It may be a legitimate site with some risky "
                "practices, or a well-disguised phishing attempt."
            )
        elif verdict == 'SAFE':
            if risk_score and int(risk_score) < 10:
                base = (
                    "This site appears to be legitimate. It shows very few or no "
                    "concerning signals across all checks — SSL, domain age, content "
                    "analysis, and external reputation all look clean."
                )
            else:
                base = (
                    "This site was classified as safe, but has some minor indicators "
                    "worth noting. Review the detailed findings if you're unsure."
                )
        elif verdict == 'UNKNOWN':
            base = (
                "The analysis couldn't reach a clear conclusion — the AI model was "
                "unable to fully parse the response. Check the detailed findings and "
                "use caution."
            )
        else:
            base = ""

        if source and 'ai' in str(source):
            base += " This verdict comes from the AI model's analysis."

        return base

    def _load_preview_image(self, image_path, max_width, max_height):
        """Load and scale a saved page preview image."""
        if not image_path or not os.path.exists(image_path):
            return None, 0, 0

        try:
            if Image and ImageTk:
                image = Image.open(image_path)
                resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.BICUBIC)
                image.thumbnail((int(max_width), int(max_height)), resample)
                photo = ImageTk.PhotoImage(image)
                return photo, photo.width(), photo.height()

            photo = tk.PhotoImage(file=image_path)
            width = photo.width()
            height = photo.height()
            if width <= 0 or height <= 0:
                return None, 0, 0

            scale = max(width / max_width, height / max_height, 1)
            if scale > 1:
                sample = int(scale) + 1
                photo = photo.subsample(sample, sample)
            return photo, photo.width(), photo.height()
        except Exception:
            return None, 0, 0

    def _display_result(self, extracted, analysis, js_analyses=None,
                         css_analyses=None, asset_results=None):
        c = self.result_canvas
        c.delete("all")
        c.update_idletasks()
        self._canvas_images = []
        self._click_regions = []

        w = c.winfo_width()
        if w < 30:
            return

        PX = 20
        PY = 12
        SECTION_GAP = 18
        TAG_H = 28
        TAG_PAD = 8
        TAG_ROW_H = 38
        DIVIDER_PAD = 12
        HEADER_H = 36
        BODY_PAD = 16

        x0 = PX
        x1 = w - PX
        y = PY
        content_w = max(x1 - x0 - (BODY_PAD * 2), 320)
        collapsed = self._collapsed_sections
        self._section_headers = []

        def register_section(sec_id, y0, y1):
            self._section_headers.append({'id': sec_id, 'y0': y0, 'y1': y1})

        def section_header(y_pos, sec_id, title, count_str=None):
            is_collapsed = sec_id in collapsed
            chevron = "▶" if is_collapsed else "▼"
            c.create_rectangle(x0, y_pos, x1, y_pos + HEADER_H,
                               fill=self.CARD_BG, outline=self.DIVIDER, width=1)
            c.create_text(x0 + 18, y_pos + HEADER_H // 2,
                          text=chevron, font=(self.FONT, 9, "bold"),
                          fill=self.ACCENT, anchor="center")
            c.create_text(x0 + 38, y_pos + HEADER_H // 2,
                          text=title, font=self.f_heading, fill=self.TEXT, anchor="w")
            if count_str:
                c.create_text(x1 - 16, y_pos + HEADER_H // 2,
                              text=count_str, font=self.f_tag,
                              fill=self.TEXT_MUTED, anchor="e")
            register_section(sec_id, y_pos, y_pos + HEADER_H)
            return y_pos + HEADER_H

        def divider(y_pos):
            c.create_line(x0 + 16, y_pos, x1 - 16, y_pos, fill=self.DIVIDER, width=1)

        def draw_text_block(tx, ty, text, font, fill, width, anchor="nw"):
            item = c.create_text(tx, ty, text=text, font=font, fill=fill,
                                 width=width, anchor=anchor)
            bbox = c.bbox(item)
            return item, (bbox[3] - bbox[1]) if bbox else 0

        def draw_tag(tx, ty, label, value, accent=False):
            text = f"{label}: {value}"
            est_w = min(max(len(text) * 7 + 30, 98), content_w - 4)
            bg = self.ACCENT_BG if accent else self.CARD_BG_ALT
            fg = self.ACCENT if accent else self.TEXT
            c.create_rectangle(tx, ty, tx + est_w, ty + TAG_H,
                               fill=bg, outline=self.DIVIDER, width=1)
            c.create_text(tx + est_w // 2, ty + TAG_H // 2,
                          text=text, font=self.f_tag, fill=fg, anchor="center")
            return est_w

        def draw_card(y_pos, body_fn):
            rect_id = c.create_rectangle(x0, y_pos, x1, y_pos + 10,
                                         fill=self.CARD_BG, outline=self.DIVIDER, width=1)
            body_bottom = body_fn(y_pos + BODY_PAD)
            c.coords(rect_id, x0, y_pos, x1, body_bottom + BODY_PAD)
            return body_bottom + BODY_PAD

        def draw_progress_bar(tx, ty, width, value, color, track=None):
            track = track or self.CARD_BG_ALT
            pct = max(0, min(int(value), 100))
            c.create_rectangle(tx, ty, tx + width, ty + 14, fill=track, outline="", width=0)
            c.create_rectangle(tx, ty, tx + max(14, width * (pct / 100)), ty + 14, fill=color, outline="", width=0)
            c.create_rectangle(tx, ty, tx + width, ty + 14, outline=self.DIVIDER, width=1)

        def draw_warning_box(tx, ty, width, title, message, level="warning", hint=None):
            palette = {
                "warning": (self.YELLOW_BG, self.YELLOW),
                "error": (self.RED_BG, self.RED),
                "info": (self.ACCENT_BG, self.ACCENT),
            }
            bg, border = palette.get(level, palette["warning"])
            rect_id = c.create_rectangle(
                tx, ty, tx + width, ty + 10, fill=bg, outline=border, width=1, dash=(4, 3)
            )
            _, title_h = draw_text_block(tx + 14, ty + 12, title, self.f_heading, self.TEXT, width - 28)
            _, msg_h = draw_text_block(tx + 14, ty + 18 + title_h, message, self.f_body, self.TEXT_SEC, width - 28)
            bottom = ty + 24 + title_h + msg_h
            if hint:
                _, hint_h = draw_text_block(tx + 14, bottom, hint, self.f_tag, self.TEXT_MUTED, width - 28)
                bottom += hint_h + 10
            c.coords(rect_id, tx, ty, tx + width, bottom)
            return bottom

        def draw_code_block(tx, ty, text, width):
            editor_bg = "#0d1117" if self.dark_mode else "#f6f8fa"
            gutter_bg = "#101720" if self.dark_mode else "#eef2f7"
            string_color = "#a5d6ff" if self.dark_mode else "#032f62"
            key_color = "#ff7b72" if self.dark_mode else "#d73a49"
            number_color = "#79c0ff" if self.dark_mode else "#005cc5"
            bool_color = "#d2a8ff" if self.dark_mode else "#6f42c1"
            plain_color = "#c9d1d9" if self.dark_mode else "#24292e"
            mono = ("Consolas", 9)

            raw = text.strip()
            try:
                parsed = json.loads(re.search(r'\{[\s\S]*\}', raw).group())
                raw = json.dumps(parsed, indent=2, ensure_ascii=False)
            except Exception:
                pass

            gutter_w = 54
            pad_x = 14
            pad_y = 34
            char_w = 7
            max_chars = max(42, int((width - gutter_w - (pad_x * 2)) / char_w))
            visual_lines = []
            source_lines = raw.splitlines()
            truncated = len(source_lines) > 160

            for line_no, line in enumerate(source_lines[:160], start=1):
                if not line:
                    visual_lines.append((line_no, "", plain_color))
                    continue

                chunks = [line[i:i + max_chars] for i in range(0, len(line), max_chars)]
                for chunk_i, chunk in enumerate(chunks):
                    stripped = chunk.lstrip()
                    if re.match(r'\s*"[^"]+"\s*:', chunk):
                        fill = key_color
                    elif stripped.startswith('"'):
                        fill = string_color
                    elif re.match(r'\s*-?\d', chunk):
                        fill = number_color
                    elif stripped.startswith(('true', 'false', 'null')):
                        fill = bool_color
                    else:
                        fill = plain_color
                    visual_lines.append((line_no if chunk_i == 0 else "", chunk, fill))

            if truncated:
                visual_lines.append(("", "... output truncated for display", self.TEXT_MUTED))

            line_h = 22
            height = max(72, pad_y + len(visual_lines) * line_h + 16)
            c.create_rectangle(tx, ty, tx + width, ty + height,
                               fill=editor_bg, outline=self.DIVIDER, width=1)
            c.create_rectangle(tx, ty, tx + gutter_w, ty + height,
                               fill=gutter_bg, outline="", width=0)
            c.create_text(tx + 14, ty + 10, text="JSON", font=self.f_tag,
                          fill=self.TEXT_MUTED, anchor="nw")

            for idx, (line_no, line, fill) in enumerate(visual_lines):
                ly = ty + pad_y + (idx * line_h)
                if line_no:
                    c.create_text(tx + gutter_w - 12, ly, text=str(line_no),
                                  font=mono, fill=self.TEXT_MUTED, anchor="ne")
                c.create_text(tx + gutter_w + pad_x, ly, text=line,
                              font=mono, fill=fill, anchor="nw")
            return height

        verdict = "SAFE"
        confidence = "?"
        risk_score = "?"
        reasons = []
        source = ""
        ai_explanation = ""
        ai_model_used = ""

        if analysis:
            ai_explanation = analysis.get('ai_explanation', '')
            ai_model_used = analysis.get('ai_model_used', '')
            if 'error' not in analysis and 'raw_response' not in analysis:
                verdict = analysis.get('verdict', 'SAFE')
                confidence = analysis.get('confidence', '?')
                risk_score = analysis.get('risk_score', '?')
                reasons = analysis.get('reasons', [])
                source = analysis.get('source', '')
            elif 'raw_response' in analysis:
                verdict = "UNKNOWN"
                reasons = [f"AI raw: {analysis['raw_response'][:200]}"]
                source = 'ai (unparsed)'
            elif 'error' in analysis:
                verdict = "SAFE"
                reasons = analysis.get('reasons', [])
                risk_score = analysis.get('risk_score', '?')
                confidence = analysis.get('confidence', '?')
                source = analysis.get('source', '')

        color_map = {
            'SAFE':       (self.GREEN,  "✓", self.GREEN_BG),
            'PHISHING':   (self.RED,    "!", self.RED_BG),
            'SUSPICIOUS': (self.YELLOW, "⚠", self.YELLOW_BG),
            'UNKNOWN':    (self.TEXT_MUTED, "?", self.ACCENT_BG),
        }
        color, icon, bg_tint = color_map.get(verdict, (self.TEXT_MUTED, "?", self.ACCENT_BG))

        def verdict_body(start_y):
            inner_x = x0 + BODY_PAD
            badge_w = min(max(len(verdict) * 24 + 72, 200), content_w)
            badge_h = 54
            c.create_rectangle(inner_x, start_y, inner_x + badge_w, start_y + badge_h,
                               fill=bg_tint, outline=color, width=1)
            c.create_text(inner_x + badge_w // 2, start_y + badge_h // 2,
                          text=f"{icon}  {verdict}", font=(self.FONT, 22, "bold"),
                          fill=color, anchor="center")

            stacked = w < 860
            text_x = inner_x if stacked else inner_x + badge_w + 28
            text_y = start_y + badge_h + 16 if stacked else start_y
            metric_w = max(content_w - (text_x - x0), 260)
            _, risk_h = draw_text_block(text_x, text_y, f"Risk Score  {risk_score}/100",
                                        self.f_heading, self.TEXT, metric_w)
            draw_progress_bar(text_x, text_y + risk_h + 6, min(metric_w, 320), int(risk_score if str(risk_score).isdigit() else 0), color)
            _, conf_h = draw_text_block(text_x, text_y + risk_h + 28,
                                        f"Confidence  {confidence}%",
                                        self.f_body_lg, self.TEXT_SEC, metric_w)
            bottom_y = max(start_y + badge_h, text_y + risk_h + conf_h + 32)

            pill_x = inner_x
            pill_y = bottom_y + 16
            if source:
                src_text = source[:40] + "…" if len(source) > 40 else source
                src_w = min(max(len(src_text) * 7 + 26, 120), 240)
                c.create_rectangle(pill_x, pill_y, pill_x + src_w, pill_y + 28,
                                   fill=self.CARD_BG, outline=self.DIVIDER, width=1)
                c.create_text(pill_x + src_w // 2, pill_y + 14, text=src_text,
                              font=self.f_tag, fill=self.TEXT_MUTED, anchor="center")
                pill_x += src_w + 10
                bottom_y = pill_y + 28
            if ai_model_used:
                model_text = f"Model: {ai_model_used.split('/')[-1].replace(':free', '')[:28]}"
                model_w = min(max(len(model_text) * 7 + 26, 130), 260)
                c.create_rectangle(pill_x, pill_y, pill_x + model_w, pill_y + 28,
                                   fill=self.CARD_BG, outline=self.DIVIDER, width=1)
                c.create_text(pill_x + model_w // 2, pill_y + 14, text=model_text,
                              font=self.f_tag, fill=self.TEXT_MUTED, anchor="center")
                bottom_y = pill_y + 28
            return bottom_y

        y = draw_card(y, verdict_body) + SECTION_GAP

        simple = self._simple_explanation(verdict, risk_score, reasons, source,
                                            analysis.get('explanation', '') if analysis else '')
        if simple:
            def explanation_body(start_y):
                c.create_text(x0 + BODY_PAD, start_y, text="AI Explanation",
                              font=self.f_section, fill=self.TEXT, anchor="nw")
                _, text_h = draw_text_block(x0 + BODY_PAD, start_y + 26, simple,
                                            self.f_body_lg, self.TEXT_SEC, content_w)
                return start_y + 26 + text_h
            y = draw_card(y, explanation_body) + SECTION_GAP

        SEC_FIND = 'findings'
        if reasons:
            y = section_header(y, SEC_FIND, "📝  Findings Summary",
                               f"{len(reasons)} reason(s)")

            if SEC_FIND not in collapsed:
                for i, reason in enumerate(reasons):
                    row_bg = self.CARD_BG if i % 2 == 0 else self.BG
                    rect_id = c.create_rectangle(x0, y, x1, y + 10, fill=row_bg, outline="", width=0)
                    _, reason_h = draw_text_block(x0 + BODY_PAD, y + 10, f"•  {reason}",
                                                  self.f_body, self.TEXT, content_w)
                    row_bottom = y + reason_h + 20
                    c.coords(rect_id, x0, y, x1, row_bottom)
                    y = row_bottom
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_SITE = 'site_info'
        y = section_header(y, SEC_SITE, "📋  Site Information")

        if SEC_SITE not in collapsed:
            # Gather tags
            tags = []
            domain = extracted.get('domain', '?')
            tags.append(("Domain", domain, False))
            http = str(extracted.get('http_status', '?'))
            tags.append(("HTTP", http, False))
            ssl_valid = extracted.get('ssl', {}).get('valid', False)
            tags.append(("SSL", "Valid" if ssl_valid else "Invalid", not ssl_valid))
            size = extracted.get('html_length', 0)
            if size >= 1_000_000:
                size_s = f"{size/1_000_000:.1f}MB"
            elif size >= 1000:
                size_s = f"{size//1000}KB"
            else:
                size_s = f"{size}B"
            tags.append(("Size", size_s, False))
            forms_n = len(extracted.get('forms', []))
            tags.append(("Forms", str(forms_n), forms_n > 0))
            if extracted.get('has_login_form'):
                tags.append(("Login Form", "Yes", True))
            links_n = len(extracted.get('external_links', []))
            tags.append(("Ext Links", str(links_n), False))
            iframes_n = len(extracted.get('iframes', []))
            if iframes_n:
                tags.append(("Iframes", str(iframes_n), True))
            scripts_n = len(extracted.get('script_sources', []))
            if scripts_n:
                tags.append(("Scripts", str(scripts_n), False))
            title = extracted.get('title', '')
            if title:
                title_s = title[:55] + "…" if len(title) > 55 else title
                tags.append(("Title", title_s, False))

            # Flow tags
            tag_x = x0 + 16
            tag_y = y + 12
            for lbl, val, accent in tags:
                tw = draw_tag(tag_x, tag_y, lbl, val, accent)
                tag_x += tw + TAG_PAD
                if tag_x + 140 > x1 - 16:
                    tag_x = x0 + 16
                    tag_y += TAG_ROW_H
            y = tag_y + TAG_ROW_H + DIVIDER_PAD
            divider(y)
            y += DIVIDER_PAD

        y += SECTION_GAP
        preview_data = extracted.get('_page_preview', {})
        SEC_PREVIEW = 'page_preview'
        if preview_data:
            label = "captured" if preview_data.get('captured') else "setup needed"
            y = section_header(y, SEC_PREVIEW, "🖼️  Website Preview", label)
            if SEC_PREVIEW not in collapsed:
                preview_path = preview_data.get('path')
                image, img_w, img_h = self._load_preview_image(preview_path, content_w, 760)
                if image:
                    self._canvas_images.append(image)
                    img_x = x0 + BODY_PAD
                    img_y = y + BODY_PAD
                    c.create_rectangle(
                        img_x - 1, img_y - 1,
                        img_x + img_w + 1, img_y + img_h + 1,
                        fill=self.CARD_BG_ALT, outline=self.DIVIDER, width=1,
                    )
                    c.create_image(img_x, img_y, image=image, anchor="nw")
                    self._click_regions.append({
                        'bbox': (img_x, img_y, img_x + img_w, img_y + img_h),
                        'callback': lambda p=preview_path: self._open_preview_zoom(p),
                    })
                    _, hint_h = draw_text_block(
                        img_x, img_y + img_h + 8,
                        "Click the preview to zoom and inspect the page.",
                        self.f_tag, self.TEXT_MUTED, content_w
                    )
                    y += img_h + hint_h + BODY_PAD + 8
                else:
                    message = preview_data.get('error') or "Screenshot preview not available for this scan."
                    hint = preview_data.get('hint', '')
                    y = draw_warning_box(
                        x0 + BODY_PAD, y + BODY_PAD, content_w,
                        "Preview unavailable",
                        message,
                        "warning",
                        hint,
                    )
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        whois_data    = extracted.get('_whois', {})
        ct_data       = extracted.get('_cert_transparency', {})
        redirect_data = extracted.get('_redirect_chain', {})
        rep_data      = extracted.get('_reputation', {})
        vt_data       = extracted.get('_virustotal', {})
        pt_data       = extracted.get('_phishtank', {})
        fav_data      = extracted.get('_favicon', {})
        vm_data       = extracted.get('_vm_detection', {})
        api_status    = extracted.get('_api_status', {})

        intel_lines = []
        age = whois_data.get('age_days')
        if age is not None:
            ico = '🔴' if age < 7 else ('🟡' if age < 30 else ('🔵' if age < 90 else '⚪'))
            reg = whois_data.get('registrar', 'unknown registrar')
            intel_lines.append(f"{ico}  Domain age: {age} days  ·  Registrar: {reg}")
        elif whois_data.get('error'):
            intel_lines.append(f"⚪  WHOIS: {str(whois_data['error'])[:80]}")
        total_certs = ct_data.get('total_certs')
        if total_certs is not None and total_certs > 0:
            ico = '🟡' if total_certs < 3 else '⚪'
            intel_lines.append(f"{ico}  Certificate Transparency: {total_certs} cert(s) found")
        elif total_certs == 0:
            intel_lines.append("🔴  Certificate Transparency: No certificates found")
        vt_pos = vt_data.get('positives')
        vt_total = vt_data.get('total')
        if vt_pos is not None and vt_total is not None:
            ico = '🔴' if vt_pos > 0 else '⚪'
            intel_lines.append(f"{ico}  VirusTotal: {vt_pos}/{vt_total} engines flagged")
        if pt_data.get('in_database'):
            ico = '🔴' if pt_data.get('verified') else '🟡'
            st = "verified phishing" if pt_data.get('verified') else "reported as phishing"
            intel_lines.append(f"{ico}  PhishTank: URL is {st}")
        scans = rep_data.get('scan_count', 0) or 0
        if scans > 0:
            avg_r = rep_data.get('avg_risk', 0) or 0
            ico = '🔴' if avg_r > 50 else ('🟡' if avg_r > 20 else '⚪')
            intel_lines.append(f"{ico}  Reputation DB: {scans} past scans, avg risk {avg_r:.0f}%")
        if fav_data.get('suspicious'):
            for r in fav_data.get('reasons', []):
                intel_lines.append(f"🟡  Favicon: {r}")
        SEC_INTEL = 'threat_intel'
        if intel_lines:
            y = section_header(y, SEC_INTEL, "🔍  Threat Intelligence",
                               f"{len(intel_lines)} indicator(s)")
            if SEC_INTEL not in collapsed:
                for line in intel_lines:
                    _, line_h = draw_text_block(x0 + BODY_PAD, y + BODY_PAD, line,
                                                self.f_body, self.TEXT_SEC, content_w)
                    y += line_h + 6
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_REDIRECT = 'redirects'
        if redirect_data:
            hops = redirect_data.get('hop_count', 0)
            label = f"{hops} hop(s)" if hops else "no redirect"
            y = section_header(y, SEC_REDIRECT, "↪  Redirects", label)
            if SEC_REDIRECT not in collapsed:
                redirected = bool(redirect_data.get('redirected') or hops)
                status_color = self.YELLOW if redirected else self.GREEN
                status_text = "YES" if redirected else "NO"
                final_url = redirect_data.get('final_url') or extracted.get('url', '')
                y += BODY_PAD
                c.create_rectangle(x0 + BODY_PAD, y, x1 - BODY_PAD, y + 52,
                                   fill=self.CARD_BG_ALT, outline=self.DIVIDER, width=1)
                c.create_text(x0 + BODY_PAD + 14, y + 16,
                              text=f"Redirect on visit: {status_text}",
                              font=self.f_heading, fill=status_color, anchor="w")
                c.create_text(x0 + BODY_PAD + 14, y + 36,
                              text=f"Hops: {hops}   Final: {final_url[:110]}",
                              font=self.f_tag, fill=self.TEXT_SEC, anchor="w")
                y += 62
                for hop in redirect_data.get('chain', [])[:8]:
                    hop_url = hop.get('url', '')
                    status = hop.get('status', '?')
                    _, hop_h = draw_text_block(
                        x0 + BODY_PAD + 8, y,
                        f"Hop {hop.get('step', '?')}: HTTP {status} -> {hop_url}",
                        self.f_body, self.TEXT_SEC, content_w - 8
                    )
                    y += hop_h + 7
                for reason in redirect_data.get('reasons', []):
                    _, reason_h = draw_text_block(
                        x0 + BODY_PAD + 8, y,
                        f"Warning: {reason}",
                        self.f_body, self.YELLOW, content_w - 8
                    )
                    y += reason_h + 7
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_VM = 'vm_detection'
        if vm_data:
            vm_label = f"{vm_data.get('finding_count', 0)} signal(s)" if vm_data.get('suspicious') else "clear"
            y = section_header(y, SEC_VM, "🧪  VM / Sandbox Detection", vm_label)
            if SEC_VM not in collapsed:
                y += BODY_PAD
                score = int(vm_data.get('score', 0) or 0)
                color_vm = self.YELLOW if vm_data.get('suspicious') else self.GREEN
                _, summary_h = draw_text_block(
                    x0 + BODY_PAD, y,
                    vm_data.get('summary', 'No VM/sandbox detection data available.'),
                    self.f_body_lg, self.TEXT, content_w
                )
                y += summary_h + 10
                draw_progress_bar(x0 + BODY_PAD, y, min(340, content_w), score, color_vm)
                c.create_text(x0 + BODY_PAD + min(340, content_w) + 12, y + 7,
                              text=f"{score}/100", font=self.f_tag,
                              fill=self.TEXT_SEC, anchor="w")
                y += 28
                findings_vm = vm_data.get('findings', [])
                if findings_vm:
                    for finding in findings_vm:
                        card_y = y
                        rect_id = c.create_rectangle(x0 + BODY_PAD, card_y, x1 - BODY_PAD, card_y + 10,
                                                     fill=self.CARD_BG_ALT, outline=self.DIVIDER, width=1)
                        _, desc_h = draw_text_block(
                            x0 + BODY_PAD + 12, card_y + 10,
                            finding.get('description', finding.get('type', 'unknown')),
                            self.f_body, self.TEXT, content_w - 24
                        )
                        _, type_h = draw_text_block(
                            x0 + BODY_PAD + 12, card_y + 16 + desc_h,
                            f"Type: {finding.get('type', '?')}  Count: {finding.get('count', 0)}",
                            self.f_tag, self.TEXT_MUTED, content_w - 24
                        )
                        bottom = card_y + desc_h + type_h + 28
                        c.coords(rect_id, x0 + BODY_PAD, card_y, x1 - BODY_PAD, bottom)
                        y = bottom + 8
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_API = 'api_status'
        if api_status:
            y = section_header(y, SEC_API, "🔌  API Status", f"{len(api_status)} service(s)")
            if SEC_API not in collapsed:
                status_palette = {
                    'worked': (self.GREEN_BG, self.GREEN, '✓'),
                    'skipped': (self.ACCENT_BG, self.ACCENT, '–'),
                    'failed': (self.RED_BG, self.RED, '!'),
                    'pending': (self.YELLOW_BG, self.YELLOW, '…'),
                }
                for item in api_status.values():
                    status = item.get('status', 'unknown')
                    bg, fg, icon_s = status_palette.get(status, (self.CARD_BG_ALT, self.TEXT_MUTED, '?'))
                    row_h = 54
                    c.create_rectangle(x0 + BODY_PAD, y + 8, x1 - BODY_PAD, y + row_h,
                                       fill=bg, outline=self.DIVIDER, width=1)
                    c.create_text(x0 + BODY_PAD + 16, y + 31, text=icon_s,
                                  font=self.f_heading, fill=fg, anchor="center")
                    label = f"{item.get('name', '?')}  •  {item.get('provider', '?')}"
                    c.create_text(x0 + BODY_PAD + 36, y + 18, text=label,
                                  font=self.f_heading, fill=self.TEXT, anchor="w")
                    detail = f"{status.upper()} — {item.get('detail', '')}"
                    c.create_text(x0 + BODY_PAD + 36, y + 36, text=detail,
                                  font=self.f_tag, fill=self.TEXT_SEC, anchor="w",
                                  width=content_w - 56)
                    y += row_h + 8
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_ASSETS = 'assets'
        if asset_results:
            js_ok  = len(asset_results['js']['downloaded'])
            js_f   = len(asset_results['js']['failed'])
            css_ok = len(asset_results['css']['downloaded'])
            css_f  = len(asset_results['css']['failed'])
            img_ok = len(asset_results['img']['downloaded'])
            img_f  = len(asset_results['img']['failed'])
            total  = js_ok + css_ok + img_ok

            y = section_header(y, SEC_ASSETS, "📦  Downloaded Assets", f"{total} total")

            if SEC_ASSETS not in collapsed:
                parts = []
                if js_ok or js_f:
                    parts.append(f"JavaScript: {js_ok} ok" + (f", {js_f} failed" if js_f else ""))
                if css_ok or css_f:
                    parts.append(f"CSS: {css_ok} ok" + (f", {css_f} failed" if css_f else ""))
                if img_ok or img_f:
                    parts.append(f"Images: {img_ok} ok" + (f", {img_f} failed" if img_f else ""))
                for part in parts:
                    _, part_h = draw_text_block(x0 + BODY_PAD, y + BODY_PAD, part,
                                                self.f_body, self.TEXT_SEC, content_w)
                    y += part_h + 6
                fnames = []
                for f in asset_results['js']['downloaded'][:2]:
                    fnames.append(os.path.basename(f['path'])[:40])
                for f in asset_results['css']['downloaded'][:2]:
                    fnames.append(os.path.basename(f['path'])[:40])
                if fnames:
                    _, fn_h = draw_text_block(x0 + BODY_PAD, y + 4,
                                              ",  ".join(fnames) + ("  …" if total > 4 else ""),
                                              self.f_tag, self.TEXT_MUTED, content_w)
                    y += fn_h + 6
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_AI = 'ai_analysis'
        if ai_explanation:
            y = section_header(y, SEC_AI, "🤖  AI Analysis Result",
                               f"via {ai_model_used.split('/')[-1].replace(':free','')}" if ai_model_used else None)

            if SEC_AI not in collapsed:
                y += BODY_PAD
                code_h = draw_code_block(x0 + BODY_PAD, y, ai_explanation, content_w)
                y += code_h + BODY_PAD

                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_JS = 'js_analysis'
        if js_analyses:
            flagged_js = [a for a in js_analyses if a.get('findings')]
            clean_js   = [a for a in js_analyses if not a.get('findings')]

            y = section_header(y, SEC_JS, "📜  JavaScript Analysis",
                               f"{len(flagged_js)} flagged / {len(js_analyses)} total")

            if SEC_JS not in collapsed and flagged_js:
                for a in flagged_js:
                    lvl   = a.get('suspicion_level', 'none')
                    icon_j = {'high': '🔴', 'medium': '🟡', 'low': '🔵', 'none': '⚪'}.get(lvl, '⚪')
                    fname  = a.get('filename', 'inline')[:50]
                    _, head_h = draw_text_block(
                        x0 + BODY_PAD, y + BODY_PAD,
                        f"{icon_j}  {fname}    score {a['score']} [{lvl}]",
                        self.f_body, self.TEXT, content_w
                    )
                    y += head_h + 6

                    for f in a.get('findings', []):
                        bar_x = x0 + BODY_PAD + 4
                        c.create_line(bar_x, y + 4, bar_x, y + 44, fill=self.DIVIDER, width=1)
                        _, type_h = draw_text_block(bar_x + 10, y + 4, f['type'],
                                                    self.f_tag, self.YELLOW, content_w - 20)
                        _, match_h = draw_text_block(bar_x + 10, y + 8 + type_h, f['match'],
                                                     self.f_tag, self.TEXT_MUTED, content_w - 20)
                        block_h = type_h + match_h + 18
                        c.create_line(bar_x, y + 4, bar_x, y + max(block_h - 4, 20),
                                      fill=self.DIVIDER, width=1)
                        y += block_h
                    y += 6

                if clean_js:
                    _, clean_h = draw_text_block(x0 + BODY_PAD, y + 8,
                                                 f"+ {len(clean_js)} clean file(s) with no issues",
                                                 self.f_tag, self.TEXT_MUTED, content_w)
                    y += clean_h + 8
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        SEC_CSS = 'css_analysis'
        if css_analyses:
            flagged_css = [a for a in css_analyses if a.get('findings')]
            clean_css   = [a for a in css_analyses if not a.get('findings')]

            if flagged_css:
                y = section_header(y, SEC_CSS, "🎨  CSS Analysis",
                                   f"{len(flagged_css)} flagged / {len(css_analyses)} total")

                if SEC_CSS not in collapsed:
                    for a in flagged_css:
                        lvl   = a.get('suspicion_level', 'none')
                        icon_c = {'high': '🔴', 'medium': '🟡', 'low': '🔵', 'none': '⚪'}.get(lvl, '⚪')
                        fname  = a.get('filename', 'inline')[:50]
                        _, head_h = draw_text_block(
                            x0 + BODY_PAD, y + BODY_PAD,
                            f"{icon_c}  {fname}    score {a['score']} [{lvl}]",
                            self.f_body, self.TEXT, content_w
                        )
                        y += head_h + 6

                        for f in a.get('findings', []):
                            bar_x = x0 + BODY_PAD + 4
                            c.create_line(bar_x, y + 4, bar_x, y + 44, fill=self.DIVIDER, width=1)
                            _, type_h = draw_text_block(bar_x + 10, y + 4, f['type'],
                                                        self.f_tag, self.YELLOW, content_w - 20)
                            _, match_h = draw_text_block(bar_x + 10, y + 8 + type_h, f['match'],
                                                         self.f_tag, self.TEXT_MUTED, content_w - 20)
                            block_h = type_h + match_h + 18
                            c.create_line(bar_x, y + 4, bar_x, y + max(block_h - 4, 20),
                                          fill=self.DIVIDER, width=1)
                            y += block_h
                        y += 6

                    if clean_css:
                        _, clean_h = draw_text_block(x0 + BODY_PAD, y + 8,
                                                     f"+ {len(clean_css)} clean file(s) with no issues",
                                                     self.f_tag, self.TEXT_MUTED, content_w)
                        y += clean_h + 8
                    y += DIVIDER_PAD
                    divider(y)
                    y += DIVIDER_PAD
            y += SECTION_GAP

        if not analysis and not js_analyses:
            c.create_text(w // 2, 140, text="Enter a URL and click Analyze…",
                          font=self.f_body, fill=self.TEXT_MUTED, anchor="center")

        y += 24
        c.config(scrollregion=(0, 0, w, y))

        # Show copy button only when results exist
        if analysis or js_analyses:
            self.copy_btn.pack(side="right")
        else:
            self.copy_btn.pack_forget()

def main():
    root = tk.Tk()
    app = PhishingAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
