#!/usr/bin/env python3
"""
URL Phishing Analyzer — Minimalist GUI
Performs deep website analysis: downloads all assets, runs JS/CSS static analysis,
offline heuristic scoring, and optional AI-powered phishing detection.
"""

import os
import json
import base64
import tkinter as tk
from tkinter import font as tkfont
import threading

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

    # ── Color Palette (GitHub-dark inspired minimal) ──────────────
    BG          = "#0d1117"
    CARD_BG     = "#161b22"
    BORDER      = "#21262d"
    DIVIDER     = "#30363d"
    TEXT        = "#e6edf3"
    TEXT_SEC    = "#8b949e"
    TEXT_MUTED  = "#6e7681"
    INPUT_BG    = "#0d1117"
    ACCENT      = "#58a6ff"
    ACCENT_BG   = "#17263d"   # blended #1f6feb @13% over #161b22
    GREEN       = "#3fb950"
    GREEN_BG    = "#1b3028"   # blended #3fb950 @13% over #161b22
    RED         = "#f85149"
    RED_BG      = "#342227"   # blended #f85149 @13% over #161b22
    YELLOW      = "#d2991d"
    YELLOW_BG   = "#2f2c21"   # blended #d2991d @13% over #161b22
    BTN_HOVER   = "#1c2840"

    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Analyzer")
        self.root.configure(bg=self.BG)
        self.root.minsize(680, 520)

        # Center window
        win_w, win_h = 820, 720
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

    # ══════════════════════════════════════════════════════════════
    #  FONTS — simple system font stack
    # ══════════════════════════════════════════════════════════════

    def _setup_fonts(self):
        self.FONT = "Helvetica"
        self.f_title   = (self.FONT, 20, "bold")
        self.f_sub     = (self.FONT, 11)
        self.f_input   = (self.FONT, 14)
        self.f_btn     = (self.FONT, 13, "bold")
        self.f_sm_btn  = (self.FONT, 10, "bold")
        self.f_verdict = (self.FONT, 26, "bold")
        self.f_heading = (self.FONT, 11, "bold")
        self.f_body    = (self.FONT, 11)
        self.f_tag     = (self.FONT, 10)
        self.f_status  = (self.FONT, 11)

    # ══════════════════════════════════════════════════════════════
    #  BUILD UI
    # ══════════════════════════════════════════════════════════════

    def _build_ui(self):
        main = tk.Frame(self.root, bg=self.BG)
        main.pack(fill="both", expand=True, padx=0, pady=0)

        # ── Header ────────────────────────────────────────────
        header = tk.Frame(main, bg=self.BG)
        header.pack(fill="x", padx=40, pady=(28, 6))
        tk.Label(header, text="Phishing Analyzer",
                 font=self.f_title, fg=self.TEXT, bg=self.BG).pack(anchor="w")
        tk.Label(header, text="Deep website analysis — offline heuristics + optional AI",
                 font=self.f_sub, fg=self.TEXT_MUTED, bg=self.BG).pack(anchor="w", pady=(2, 0))

        # ── API Key Section ───────────────────────────────────
        self._build_api_key_section(main)

        # ── URL Input ─────────────────────────────────────────
        input_frame = tk.Frame(main, bg=self.BG)
        input_frame.pack(fill="x", padx=40, pady=(10, 8))

        # Input row: entry + button side by side
        row = tk.Frame(input_frame, bg=self.BG)
        row.pack(fill="x")

        # Entry with subtle border
        entry_border = tk.Frame(row, bg=self.BORDER, bd=0,
                                highlightthickness=1,
                                highlightbackground=self.BORDER)
        entry_border.pack(side="left", fill="x", expand=True, ipady=1)

        self.url_var = tk.StringVar()
        self.entry = tk.Entry(
            entry_border, textvariable=self.url_var,
            font=self.f_input, bg=self.INPUT_BG,
            fg=self.TEXT, insertbackground=self.TEXT,
            relief="flat", bd=0, highlightthickness=0,
        )
        self.entry.pack(fill="x", expand=True, padx=12, ipady=8)

        self._placeholder_active = True
        self._set_placeholder()
        self.entry.bind("<FocusIn>", self._on_focus_in)
        self.entry.bind("<FocusOut>", self._on_focus_out)
        self.entry.bind("<Return>", lambda e: self._start_analysis())

        # Scan button
        self.analyze_btn = tk.Label(
            row, text="  Analyze  ",
            font=self.f_btn, fg="#ffffff",
            bg=self.ACCENT, cursor="hand2",
            relief="flat", bd=0,
            padx=22, pady=8,
        )
        self.analyze_btn.pack(side="left", padx=(10, 0))
        self.analyze_btn.bind("<Button-1>", lambda e: self._start_analysis())
        self.analyze_btn.bind("<Enter>", lambda e: self.analyze_btn.config(bg="#4090e0"))
        self.analyze_btn.bind("<Leave>", lambda e: self.analyze_btn.config(bg=self.ACCENT))

        # ── Status label + Copy button row ────────────────────
        status_row = tk.Frame(main, bg=self.BG)
        status_row.pack(fill="x", padx=44, pady=(0, 4))

        self.status_var = tk.StringVar(value="")
        self.status_label = tk.Label(
            status_row, textvariable=self.status_var,
            font=self.f_status, fg=self.TEXT_MUTED, bg=self.BG,
            anchor="w",
        )
        self.status_label.pack(side="left", fill="x", expand=True)

        self.copy_btn = tk.Label(
            status_row, text="📋 Copy All",
            font=self.f_tag, fg=self.TEXT_MUTED, bg=self.CARD_BG,
            cursor="hand2", relief="flat", bd=0,
            padx=10, pady=4,
            highlightthickness=1, highlightbackground=self.DIVIDER,
        )
        self.copy_btn.pack(side="right")
        self.copy_btn.bind("<Button-1>", lambda e: self._copy_all_results())
        self.copy_btn.bind("<Enter>", lambda e: self.copy_btn.config(bg=self.BTN_HOVER, fg=self.TEXT))
        self.copy_btn.bind("<Leave>", lambda e: self.copy_btn.config(bg=self.CARD_BG, fg=self.TEXT_MUTED))
        # Hidden until results exist
        self.copy_btn.pack_forget()

        # ── Result canvas with scrollbar ──────────────────────
        result_wrapper = tk.Frame(main, bg=self.BG)
        result_wrapper.pack(fill="both", expand=True, padx=40, pady=(4, 24))
        result_wrapper.grid_rowconfigure(0, weight=1)
        result_wrapper.grid_columnconfigure(0, weight=1)

        self.result_canvas = tk.Canvas(
            result_wrapper, bg=self.BG, highlightthickness=0, bd=0,
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

    # ══════════════════════════════════════════════════════════════
    #  API KEY SECTION — three labeled fields, collapsible
    # ══════════════════════════════════════════════════════════════

    def _build_api_key_section(self, parent):
        # Outer card
        self._api_card = tk.Frame(parent, bg=self.CARD_BG, bd=0,
                                  highlightthickness=1, highlightbackground=self.BORDER)
        self._api_card.pack(fill="x", padx=40, pady=(0, 8))

        # Header row — click to expand/collapse
        header = tk.Frame(self._api_card, bg=self.CARD_BG, cursor="hand2")
        header.pack(fill="x", padx=14, pady=(8, 0))

        def _toggle():
            self._toggle_api_section()

        header.bind("<Button-1>", lambda e: _toggle())

        self._api_chevron = tk.Label(header, text="▶", font=(self.FONT, 10),
                                     fg=self.TEXT_MUTED, bg=self.CARD_BG, cursor="hand2")
        self._api_chevron.pack(side="left", padx=(0, 8))
        self._api_chevron.bind("<Button-1>", lambda e: _toggle())

        self._api_header_count = tk.Label(
            header, text="", font=self.f_tag, fg=self.TEXT_MUTED,
            bg=self.CARD_BG, cursor="hand2")
        self._api_header_count.pack(side="right")
        self._api_header_count.bind("<Button-1>", lambda e: _toggle())

        self._api_header_label = tk.Label(
            header, text="API Keys",
            font=self.f_heading, fg=self.TEXT_SEC, bg=self.CARD_BG, cursor="hand2")
        self._api_header_label.pack(side="left")
        self._api_header_label.bind("<Button-1>", lambda e: _toggle())

        self._refresh_api_header()

        # Body frame (hidden by default)
        self._api_body = tk.Frame(self._api_card, bg=self.CARD_BG)
        # Not packed initially — toggled on expand

        # Three key rows
        for key_id, meta in self._keys.items():
            self._build_key_row(self._api_body, key_id, meta)

        # Apply button at the bottom
        btn_row = tk.Frame(self._api_body, bg=self.CARD_BG)
        btn_row.pack(fill="x", padx=14, pady=(4, 10))

        apply_btn = tk.Label(
            btn_row, text=" Apply All Keys ",
            font=self.f_sm_btn, fg="#ffffff", bg=self.ACCENT,
            cursor="hand2", relief="flat", bd=0, padx=14, pady=5,
        )
        apply_btn.pack(side="left")
        apply_btn.bind("<Button-1>", lambda e: self._apply_all_keys())
        apply_btn.bind("<Enter>", lambda e: apply_btn.config(bg="#4090e0"))
        apply_btn.bind("<Leave>", lambda e: apply_btn.config(bg=self.ACCENT))

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

        row = tk.Frame(parent, bg=self.CARD_BG)
        row.pack(fill="x", padx=14, pady=(10, 0))

        # Label row
        label_row = tk.Frame(row, bg=self.CARD_BG)
        label_row.pack(fill="x")

        tk.Label(label_row, text=label, font=self.f_heading,
                 fg=self.TEXT, bg=self.CARD_BG).pack(side="left")
        tk.Label(label_row, text=desc, font=self.f_tag,
                 fg=self.TEXT_MUTED, bg=self.CARD_BG).pack(side="left", padx=(8, 0))

        # Provider dropdown for AI key
        if key_id == 'ai':
            provider_options = ['openrouter', 'deepseek']
            provider_dropdown = tk.OptionMenu(
                label_row, self._ai_provider, *provider_options,
                command=lambda _: self._on_provider_changed()
            )
            provider_dropdown.config(
                font=self.f_tag, fg=self.TEXT, bg=self.CARD_BG,
                activebackground=self.BTN_HOVER, activeforeground=self.TEXT,
                relief="flat", bd=0, highlightthickness=0,
            )
            # Style the dropdown menu
            provider_dropdown['menu'].config(
                font=self.f_tag, bg=self.CARD_BG, fg=self.TEXT,
                activebackground=self.BTN_HOVER, activeforeground=self.TEXT,
                relief="flat", bd=1,
            )
            provider_dropdown.pack(side="left", padx=(12, 0))

        # Model dropdown row (visible for OpenRouter)
        if key_id == 'ai':
            model_row = tk.Frame(row, bg=self.CARD_BG)
            model_row.pack(fill="x", pady=(6, 0))

            tk.Label(model_row, text="Model:", font=self.f_tag,
                     fg=self.TEXT_MUTED, bg=self.CARD_BG).pack(side="left")

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
                font=self.f_tag, bg=self.CARD_BG, fg=self.TEXT,
                activebackground=self.BTN_HOVER, activeforeground=self.TEXT,
                relief="flat", bd=1,
            )
            model_dropdown.pack(side="left", padx=(6, 0))

            # Label showing fallback info
            self._model_hint = tk.Label(
                model_row, text="(tries next if fails)",
                font=self.f_tag, fg=self.TEXT_MUTED, bg=self.CARD_BG,
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
                              fg=dot_color, bg=self.CARD_BG)
        status_dot.pack(side="right")

        # Input row
        input_row = tk.Frame(row, bg=self.CARD_BG)
        input_row.pack(fill="x", pady=(4, 0))

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
            self.status_var.set(f"API keys applied: {names}{model_info}")
        else:
            self.status_var.set("No API keys entered — using .env if available")

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
        if self._placeholder_active:
            self.entry.delete(0, tk.END)
            self.entry.config(fg=self.TEXT)
            self._placeholder_active = False

    def _on_focus_out(self, event):
        if not self.url_var.get().strip():
            self._set_placeholder()

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
            self.status_var.set("Please enter a URL to analyze")
            return

        self.is_analyzing = True
        self.result_canvas.delete("all")
        self._current_result = None
        self.status_var.set("Downloading page…")
        self.analyze_btn.config(bg=self.TEXT_MUTED, text="Analyzing…")

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
        self.root.after(0, lambda: self.status_var.set(text))

    def _show_error(self, msg):
        def _do():
            self.status_var.set(msg)
            self.is_analyzing = False
            self.analyze_btn.config(bg=self.ACCENT, text="  Analyze  ")
        self.root.after(0, _do)

    def _on_analysis_complete(self, extracted, analysis, js_analyses, css_analyses, asset_results):
        self.is_analyzing = False
        self.analyze_btn.config(bg=self.ACCENT, text="  Analyze  ")

        domain = extracted.get('domain', 'unknown')
        source = analysis.get('source', '') if analysis else ''
        src_note = f" • {source}" if source else ""
        self.status_var.set(f"Analysis complete • saved to scraped_sites/{domain}/{src_note}")

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
        cy = self.result_canvas.canvasy(event.y)
        for sec in self._section_headers:
            if sec['y0'] <= cy <= sec['y1']:
                self._toggle_section(sec['id'])
                return

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

        if any([whois, ct, redir, vt, pt, rep, fav]):
            lines.append("── Threat Intelligence ──")
        if whois.get('age_days') is not None:
            lines.append(f"WHOIS:     {whois['age_days']} days old, registrar: {whois.get('registrar','?')}")
        if ct.get('total_certs') is not None:
            lines.append(f"Cert Trans: {ct['total_certs']} certs found")
        if redir.get('hop_count', 0) > 0:
            lines.append(f"Redirects: {redir['hop_count']} hops")
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
            self.status_var.set("📋 Results copied to clipboard")
        except Exception:
            self.status_var.set("⚠ Could not copy to clipboard")

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

    def _display_result(self, extracted, analysis, js_analyses=None,
                         css_analyses=None, asset_results=None):
        c = self.result_canvas
        c.delete("all")
        c.update_idletasks()

        w = c.winfo_width()
        if w < 30:
            return

        # ── Spacing constants ──────────────────────────────────
        PX          = 20
        PY          = 10
        SECTION_GAP = 18
        LINE_H      = 26
        TAG_H       = 26
        TAG_PAD     = 8
        TAG_ROW_H   = 34
        FINDING_H   = 36
        FILE_GAP    = 6
        DIVIDER_PAD = 12
        HEADER_H    = 32
        CHEVRON_W   = 20   # width reserved for collapse chevron

        x0 = PX
        x1 = w - PX
        y  = PY

        self._section_headers = []  # reset for click tracking

        # ── Helpers ────────────────────────────────────────────

        collapsed = self._collapsed_sections

        def register_section(sec_id, y0, y1):
            """Record a section header for click detection."""
            self._section_headers.append({'id': sec_id, 'y0': y0, 'y1': y1})

        def section_header(y_pos, sec_id, title, count_str=None):
            """Draw a clickable section header. Returns y after header."""
            is_collapsed = sec_id in collapsed
            chevron = "▶" if is_collapsed else "▼"

            c.create_rectangle(x0, y_pos, x1, y_pos + HEADER_H,
                               fill=self.CARD_BG, outline="", width=0)
            c.create_line(x0, y_pos, x1, y_pos, fill=self.DIVIDER, width=1)
            c.create_line(x0, y_pos + HEADER_H, x1, y_pos + HEADER_H,
                          fill=self.DIVIDER, width=1)

            # Chevron (clickable indicator)
            c.create_text(x0 + 18, y_pos + HEADER_H // 2,
                          text=chevron,
                          font=(self.FONT, 9, "bold"), fill=self.ACCENT, anchor="center")

            # Title
            c.create_text(x0 + 18 + CHEVRON_W, y_pos + HEADER_H // 2,
                          text=title,
                          font=self.f_heading, fill=self.TEXT, anchor="w")

            # Count badge (right side)
            if count_str:
                c.create_text(x1 - 16, y_pos + HEADER_H // 2,
                              text=count_str, font=self.f_tag,
                              fill=self.TEXT_MUTED, anchor="e")

            # Cursor hint — subtle hover bar on the right
            c.create_text(x1 - 6, y_pos + HEADER_H // 2,
                          text="─", font=(self.FONT, 9),
                          fill=self.DIVIDER, anchor="e")

            # Register click region
            register_section(sec_id, y_pos, y_pos + HEADER_H)
            return y_pos + HEADER_H

        def divider(y_pos):
            c.create_line(x0 + 16, y_pos, x1 - 16, y_pos,
                          fill=self.DIVIDER, width=1)

        def draw_tag(tx, ty, label, value, accent=False):
            text = f"{label}: {value}"
            est_w = len(text) * 7 + 22
            bg = self.ACCENT_BG if accent else self.CARD_BG
            fg = self.ACCENT if accent else self.TEXT_SEC
            c.create_rectangle(tx, ty, tx + est_w, ty + TAG_H,
                               fill=bg, outline=self.DIVIDER, width=1)
            c.create_text(tx + est_w // 2, ty + TAG_H // 2,
                          text=text, font=self.f_tag, fill=fg, anchor="center")
            return est_w

        # ══════════════════════════════════════════════════════════
        #  PARSE VERDICT
        # ══════════════════════════════════════════════════════════
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

        # ══════════════════════════════════════════════════════════
        #  1. VERDICT CARD (always visible, not collapsible)
        # ══════════════════════════════════════════════════════════
        V_PAD    = 20
        BADGE_H  = 46
        BADGE_W  = max(len(verdict) * 22 + 52, 140)
        CARD_H   = V_PAD * 2 + BADGE_H

        c.create_rectangle(x0, y, x1, y + CARD_H,
                           fill=self.CARD_BG, outline="", width=0)
        c.create_line(x0, y, x1, y, fill=self.DIVIDER, width=1)
        c.create_line(x0, y + CARD_H, x1, y + CARD_H,
                      fill=self.DIVIDER, width=1)

        # Badge pill
        bad_x = x0 + 20
        bad_y = y + V_PAD
        c.create_rectangle(bad_x, bad_y, bad_x + BADGE_W, bad_y + BADGE_H,
                           fill=bg_tint, outline="", width=0)
        c.create_text(bad_x + BADGE_W // 2, bad_y + BADGE_H // 2,
                      text=f"{icon}  {verdict}",
                      font=(self.FONT, 23, "bold"), fill=color, anchor="center")

        # Risk + Confidence
        info_x = bad_x + BADGE_W + 32
        mid_y = y + CARD_H // 2
        c.create_text(info_x, mid_y - 11,
                      text=f"Risk Score: {risk_score} / 100",
                      font=self.f_heading, fill=self.TEXT, anchor="w")
        c.create_text(info_x, mid_y + 11,
                      text=f"Confidence: {confidence}%",
                      font=self.f_body, fill=self.TEXT_SEC, anchor="w")

        # Source tag
        if source:
            src_text = source[:28] + "…" if len(source) > 28 else source
            src_w = min(len(src_text) * 8 + 24, 220)
            src_r = x1 - 16
            c.create_rectangle(src_r - src_w, bad_y + 6,
                               src_r, bad_y + BADGE_H - 6,
                               fill=self.CARD_BG, outline=self.DIVIDER, width=1)
            c.create_text(src_r - src_w // 2, bad_y + BADGE_H // 2,
                          text=src_text, font=self.f_tag,
                          fill=self.TEXT_MUTED, anchor="center")

        # Model used badge (tiny, under source)
        if ai_model_used:
            model_short = ai_model_used.split('/')[-1].replace(':free', '')[:20]
            c.create_text(src_r - 10, bad_y + BADGE_H - 2,
                          text=f"via {model_short}",
                          font=(self.FONT, 8), fill=self.TEXT_MUTED, anchor="se")

        y += CARD_H + SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  PLAIN-LANGUAGE EXPLANATION
        # ══════════════════════════════════════════════════════════
        simple = self._simple_explanation(verdict, risk_score, reasons, source,
                                            analysis.get('explanation', '') if analysis else '')
        if simple:
            explain_h = 52
            c.create_rectangle(x0, y, x1, y + explain_h,
                               fill=self.CARD_BG, outline="", width=0)
            c.create_line(x0, y, x1, y, fill=self.DIVIDER, width=1)
            c.create_line(x0, y + explain_h, x1, y + explain_h,
                          fill=self.DIVIDER, width=1)

            # Wrap text to fit canvas width
            max_chars = max(int((x1 - x0 - 32) / 6.5), 40)
            wrapped = simple
            if len(wrapped) > max_chars:
                # Split into two lines
                mid = wrapped.rfind(' ', 0, max_chars)
                if mid < max_chars // 2:
                    mid = max_chars
                line1 = wrapped[:mid].strip()
                line2 = wrapped[mid:].strip()
                c.create_text(x0 + 16, y + 14,
                              text=line1, font=self.f_body,
                              fill=self.TEXT_SEC, anchor="nw")
                c.create_text(x0 + 16, y + 34,
                              text=line2, font=self.f_body,
                              fill=self.TEXT_SEC, anchor="nw")
            else:
                c.create_text(x0 + 16, y + explain_h // 2,
                              text=wrapped, font=self.f_body,
                              fill=self.TEXT_SEC, anchor="w")

            y += explain_h + SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  2. SITE INFORMATION (collapsible)
        # ══════════════════════════════════════════════════════════
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

        # ══════════════════════════════════════════════════════════
        #  3. THREAT INTELLIGENCE (collapsible)
        # ══════════════════════════════════════════════════════════
        whois_data    = extracted.get('_whois', {})
        ct_data       = extracted.get('_cert_transparency', {})
        redirect_data = extracted.get('_redirect_chain', {})
        rep_data      = extracted.get('_reputation', {})
        vt_data       = extracted.get('_virustotal', {})
        pt_data       = extracted.get('_phishtank', {})
        fav_data      = extracted.get('_favicon', {})

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
        hops = redirect_data.get('hop_count', 0)
        if hops > 0:
            ico = '🟡' if redirect_data.get('cross_domain') else '⚪'
            tail = " (cross-domain)" if redirect_data.get('cross_domain') else ""
            intel_lines.append(f"{ico}  Redirect chain: {hops} hop(s){tail}")
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
                igap = 14
                for line in intel_lines:
                    c.create_text(x0 + 20, y + igap,
                                  text=line, font=self.f_body,
                                  fill=self.TEXT_SEC, anchor="nw")
                    y += LINE_H
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  4. DOWNLOADED ASSETS (collapsible)
        # ══════════════════════════════════════════════════════════
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
                apad = 14
                parts = []
                if js_ok or js_f:
                    parts.append(f"JavaScript: {js_ok} ok" + (f", {js_f} failed" if js_f else ""))
                if css_ok or css_f:
                    parts.append(f"CSS: {css_ok} ok" + (f", {css_f} failed" if css_f else ""))
                if img_ok or img_f:
                    parts.append(f"Images: {img_ok} ok" + (f", {img_f} failed" if img_f else ""))
                for part in parts:
                    c.create_text(x0 + 20, y + apad,
                                  text=part, font=self.f_body,
                                  fill=self.TEXT_SEC, anchor="nw")
                    y += LINE_H
                fnames = []
                for f in asset_results['js']['downloaded'][:2]:
                    fnames.append(os.path.basename(f['path'])[:40])
                for f in asset_results['css']['downloaded'][:2]:
                    fnames.append(os.path.basename(f['path'])[:40])
                if fnames:
                    c.create_text(x0 + 20, y + 4,
                                  text=",  ".join(fnames) + ("  …" if total > 4 else ""),
                                  font=self.f_tag, fill=self.TEXT_MUTED, anchor="nw")
                    y += 22
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  5. AI ANALYSIS EXPLANATION (new — collapsible)
        # ══════════════════════════════════════════════════════════
        SEC_AI = 'ai_analysis'
        if ai_explanation:
            y = section_header(y, SEC_AI, "🤖  AI Analysis Result",
                               f"via {ai_model_used.split('/')[-1].replace(':free','')}" if ai_model_used else None)

            if SEC_AI not in collapsed:
                apad = 14
                # Display the AI's full explanation text, wrapped
                max_chars = max(int((x1 - x0 - 40) / 6.5), 30)
                # Break into lines for readability
                paragraphs = ai_explanation.replace('\r\n', '\n').replace('\r', '\n').split('\n')
                for para in paragraphs:
                    if not para.strip():
                        y += 8
                        continue
                    # Word-wrap
                    words = para.split()
                    line = ""
                    for word in words:
                        test = line + (" " if line else "") + word
                        if len(test) <= max_chars:
                            line = test
                        else:
                            if line:
                                c.create_text(x0 + 20, y + apad,
                                              text=line, font=self.f_body,
                                              fill=self.TEXT, anchor="nw")
                                y += LINE_H
                            line = word
                    if line:
                        c.create_text(x0 + 20, y + apad,
                                      text=line, font=self.f_body,
                                      fill=self.TEXT, anchor="nw")
                        y += LINE_H

                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  6. JAVASCRIPT ANALYSIS (collapsible)
        # ══════════════════════════════════════════════════════════
        SEC_JS = 'js_analysis'
        if js_analyses:
            flagged_js = [a for a in js_analyses if a.get('findings')]
            clean_js   = [a for a in js_analyses if not a.get('findings')]

            y = section_header(y, SEC_JS, "📜  JavaScript Analysis",
                               f"{len(flagged_js)} flagged / {len(js_analyses)} total")

            if SEC_JS not in collapsed and flagged_js:
                jpad = 14
                for a in flagged_js:
                    lvl   = a.get('suspicion_level', 'none')
                    icon_j = {'high': '🔴', 'medium': '🟡', 'low': '🔵', 'none': '⚪'}.get(lvl, '⚪')
                    fname  = a.get('filename', 'inline')[:50]

                    c.create_text(x0 + 20, y + jpad,
                                  text=f"{icon_j}  {fname}",
                                  font=self.f_body, fill=self.TEXT, anchor="nw")
                    c.create_text(x1 - 20, y + jpad,
                                  text=f"score {a['score']}  [{lvl}]",
                                  font=self.f_tag, fill=self.TEXT_MUTED, anchor="e")
                    y += LINE_H

                    for f in a.get('findings', []):
                        match_txt = f['match']
                        if len(match_txt) > 105:
                            match_txt = match_txt[:102] + "…"
                        bar_x = x0 + 24
                        c.create_line(bar_x, y + 4, bar_x, y + FINDING_H - 4,
                                      fill=self.DIVIDER, width=1)
                        c.create_text(bar_x + 10, y + 5,
                                      text=f"{f['type']}", font=self.f_tag,
                                      fill=self.YELLOW, anchor="nw")
                        c.create_text(bar_x + 10, y + 22,
                                      text=match_txt, font=self.f_tag,
                                      fill=self.TEXT_MUTED, anchor="nw")
                        y += FINDING_H
                    y += FILE_GAP

                if clean_js:
                    c.create_text(x0 + 20, y + 8,
                                  text=f"+ {len(clean_js)} clean file(s) with no issues",
                                  font=self.f_tag, fill=self.TEXT_MUTED, anchor="nw")
                    y += 24
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  7. CSS ANALYSIS (collapsible)
        # ══════════════════════════════════════════════════════════
        SEC_CSS = 'css_analysis'
        if css_analyses:
            flagged_css = [a for a in css_analyses if a.get('findings')]
            clean_css   = [a for a in css_analyses if not a.get('findings')]

            if flagged_css:
                y = section_header(y, SEC_CSS, "🎨  CSS Analysis",
                                   f"{len(flagged_css)} flagged / {len(css_analyses)} total")

                if SEC_CSS not in collapsed:
                    cpad = 14
                    for a in flagged_css:
                        lvl   = a.get('suspicion_level', 'none')
                        icon_c = {'high': '🔴', 'medium': '🟡', 'low': '🔵', 'none': '⚪'}.get(lvl, '⚪')
                        fname  = a.get('filename', 'inline')[:50]

                        c.create_text(x0 + 20, y + cpad,
                                      text=f"{icon_c}  {fname}",
                                      font=self.f_body, fill=self.TEXT, anchor="nw")
                        c.create_text(x1 - 20, y + cpad,
                                      text=f"score {a['score']}  [{lvl}]",
                                      font=self.f_tag, fill=self.TEXT_MUTED, anchor="e")
                        y += LINE_H

                        for f in a.get('findings', []):
                            match_txt = f['match']
                            if len(match_txt) > 105:
                                match_txt = match_txt[:102] + "…"
                            bar_x = x0 + 24
                            c.create_line(bar_x, y + 4, bar_x, y + FINDING_H - 4,
                                          fill=self.DIVIDER, width=1)
                            c.create_text(bar_x + 10, y + 5,
                                          text=f"{f['type']}", font=self.f_tag,
                                          fill=self.YELLOW, anchor="nw")
                            c.create_text(bar_x + 10, y + 22,
                                          text=match_txt, font=self.f_tag,
                                          fill=self.TEXT_MUTED, anchor="nw")
                            y += FINDING_H
                        y += FILE_GAP

                    if clean_css:
                        c.create_text(x0 + 20, y + 8,
                                      text=f"+ {len(clean_css)} clean file(s) with no issues",
                                      font=self.f_tag, fill=self.TEXT_MUTED, anchor="nw")
                        y += 24
                    y += DIVIDER_PAD
                    divider(y)
                    y += DIVIDER_PAD
            y += SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  8. FINDINGS SUMMARY (collapsible)
        # ══════════════════════════════════════════════════════════
        SEC_FIND = 'findings'
        if reasons:
            y = section_header(y, SEC_FIND, "📝  Findings Summary",
                               f"{len(reasons)} reason(s)")

            if SEC_FIND not in collapsed:
                for i, reason in enumerate(reasons):
                    text = reason[:115] + "…" if len(reason) > 115 else reason
                    row_bg = self.CARD_BG if i % 2 == 0 else self.BG
                    c.create_rectangle(x0, y, x1, y + LINE_H,
                                       fill=row_bg, outline="", width=0)
                    c.create_text(x0 + 20, y + LINE_H // 2,
                                  text=f"•  {text}",
                                  font=self.f_body, fill=self.TEXT, anchor="w")
                    y += LINE_H
                y += DIVIDER_PAD
                divider(y)
                y += DIVIDER_PAD
            y += SECTION_GAP

        # ══════════════════════════════════════════════════════════
        #  EMPTY STATE
        # ══════════════════════════════════════════════════════════
        if not analysis and not js_analyses:
            c.create_text(w // 2, 140, text="Enter a URL and click Analyze…",
                          font=self.f_body, fill=self.TEXT_MUTED, anchor="center")

        # ── Scroll region ───────────────────────────────────────
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
