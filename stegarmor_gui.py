#!/usr/bin/env python3
"""
StegArmor GUI - Encrypted Steganography Tool (Desktop Interface)
==================================================================

A cross-platform (Windows / Linux) Tkinter GUI front-end for StegArmor.
This file contains NO cryptography or steganography logic of its own --
it imports and calls the exact same tested functions from stegarmor.py,
so the CLI and GUI always behave identically. Keep both files in the
same folder.

Run with:
    python stegarmor_gui.py          (Windows)
    python3 stegarmor_gui.py         (Linux / Kali)

Dependencies (same as the CLI):
    pip install pillow cryptography

Author:  [YOUR NAME HERE]
License: MIT
Repository: [INSERT GITHUB REPOSITORY LINK HERE]
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from PIL import Image, ImageTk

# --- Import the already-tested core engine from stegarmor.py -------------
# stegarmor.py must live in the same directory as this file.
try:
    from stegarmor import (
        encrypt_message,
        decrypt_message,
        embed_data_in_image,
        extract_data_from_image,
        get_image_capacity_bytes,
        StegArmorError,
        InsufficientCapacityError,
        InvalidPasswordError,
        NoHiddenDataError,
    )
except ImportError:
    print("[!] Could not find stegarmor.py. Make sure stegarmor_gui.py and "
          "stegarmor.py are in the same folder.", file=sys.stderr)
    sys.exit(1)


APP_TITLE = "StegArmor - Encrypted Image Steganography"
THUMBNAIL_SIZE = (260, 260)
BG_COLOR = "#1e1e2e"
PANEL_COLOR = "#282838"
ACCENT_COLOR = "#7aa2f7"
TEXT_COLOR = "#e0e0e8"
SUCCESS_COLOR = "#9ece6a"
ERROR_COLOR = "#f7768e"


class StegArmorGUI(tk.Tk):
    """Main application window with Embed and Extract tabs."""

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("880x640")
        self.minsize(760, 560)
        self.configure(bg=BG_COLOR)

        self._configure_styles()
        self._build_layout()

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------
    def _configure_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL_COLOR, foreground=TEXT_COLOR,
                         padding=(16, 8), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", ACCENT_COLOR)],
                  foreground=[("selected", "#101018")])

        style.configure("TFrame", background=BG_COLOR)
        style.configure("Panel.TFrame", background=PANEL_COLOR)
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=PANEL_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=BG_COLOR, foreground=TEXT_COLOR,
                         font=("Segoe UI", 16, "bold"))
        style.configure("Sub.TLabel", background=BG_COLOR, foreground="#9a9ab0",
                         font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=BG_COLOR, font=("Segoe UI", 9, "italic"))

        style.configure("TEntry", fieldbackground="#33334a", foreground=TEXT_COLOR,
                         insertcolor=TEXT_COLOR, borderwidth=0, padding=6)
        style.configure("TButton", background=ACCENT_COLOR, foreground="#101018",
                         font=("Segoe UI", 10, "bold"), padding=(12, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#5e83d8"), ("disabled", "#4a4a5c")])
        style.configure("Secondary.TButton", background="#3a3a4e", foreground=TEXT_COLOR,
                         font=("Segoe UI", 9), padding=(10, 6))
        style.map("Secondary.TButton", background=[("active", "#4a4a60")])
        style.configure("Horizontal.TProgressbar", background=ACCENT_COLOR,
                         troughcolor=PANEL_COLOR, borderwidth=0)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_layout(self):
        header = ttk.Frame(self, padding=(20, 16, 20, 8))
        header.pack(fill="x")
        ttk.Label(header, text="StegArmor", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="AES-256 encrypted message hiding inside PNG images",
                  style="Sub.TLabel").pack(anchor="w")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        self.embed_tab = EmbedTab(notebook)
        self.extract_tab = ExtractTab(notebook)
        notebook.add(self.embed_tab, text="  Embed / Hide Message  ")
        notebook.add(self.extract_tab, text="  Extract / Reveal Message  ")

        self.status_var = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self, textvariable=self.status_var, style="Status.TLabel",
                                padding=(16, 4))
        status_bar.pack(fill="x", side="bottom")


class BaseTab(ttk.Frame):
    """Shared helpers for the Embed and Extract tabs."""

    def __init__(self, parent):
        super().__init__(parent, padding=16)
        self.image_path = tk.StringVar()
        self.password = tk.StringVar()
        self.thumbnail_image = None  # keep a reference so it isn't garbage-collected

    def browse_image(self, target_var: tk.StringVar, thumbnail_label: ttk.Label = None):
        path = filedialog.askopenfilename(
            title="Select PNG image",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if path:
            target_var.set(path)
            if thumbnail_label is not None:
                self._update_thumbnail(path, thumbnail_label)

    def _update_thumbnail(self, path, label: ttk.Label):
        try:
            img = Image.open(path)
            img.thumbnail(THUMBNAIL_SIZE)
            photo = ImageTk.PhotoImage(img)
            label.configure(image=photo, text="")
            self.thumbnail_image = photo  # prevent garbage collection
        except Exception:
            label.configure(image="", text="[Preview unavailable]")

    def set_status(self, message: str, is_error: bool = False):
        root = self.winfo_toplevel()
        root.status_var.set(message)

    def show_password_toggle(self, entry: ttk.Entry, var: tk.StringVar, parent):
        show_var = tk.BooleanVar(value=False)

        def toggle():
            entry.configure(show="" if show_var.get() else "*")

        chk = ttk.Checkbutton(parent, text="Show", variable=show_var, command=toggle,
                               style="Secondary.TButton")
        return chk


class EmbedTab(BaseTab):
    def __init__(self, parent):
        super().__init__(parent)
        self.output_path = tk.StringVar()
        self._build()

    def _build(self):
        left = ttk.Frame(self)
        left.pack(side="left", fill="both", expand=True, padx=(0, 16))
        right = ttk.Frame(self, style="Panel.TFrame", padding=12)
        right.pack(side="right", fill="y")

        # --- Left column: form ---
        ttk.Label(left, text="1. Cover Image (PNG)").pack(anchor="w", pady=(0, 4))
        row1 = ttk.Frame(left)
        row1.pack(fill="x", pady=(0, 12))
        ttk.Entry(row1, textvariable=self.image_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row1, text="Browse...", style="Secondary.TButton",
                   command=lambda: self.browse_image(self.image_path, self.preview_label)
                   ).pack(side="left", padx=(8, 0))

        self.capacity_label = ttk.Label(left, text="Select an image to see capacity.",
                                         style="Sub.TLabel")
        self.capacity_label.pack(anchor="w", pady=(0, 12))
        self.image_path.trace_add("write", lambda *_: self._refresh_capacity())

        ttk.Label(left, text="2. Secret Message").pack(anchor="w", pady=(0, 4))
        self.message_text = tk.Text(left, height=6, bg="#33334a", fg=TEXT_COLOR,
                                     insertbackground=TEXT_COLOR, relief="flat", padx=8, pady=8)
        self.message_text.pack(fill="x", pady=(0, 12))

        ttk.Label(left, text="3. Password").pack(anchor="w", pady=(0, 4))
        pw_row = ttk.Frame(left)
        pw_row.pack(fill="x", pady=(0, 12))
        pw_entry = ttk.Entry(pw_row, textvariable=self.password, show="*")
        pw_entry.pack(side="left", fill="x", expand=True)
        self.show_password_toggle(pw_entry, self.password, pw_row).pack(side="left", padx=(8, 0))

        ttk.Label(left, text="4. Save Stego Image As").pack(anchor="w", pady=(0, 4))
        row2 = ttk.Frame(left)
        row2.pack(fill="x", pady=(0, 16))
        ttk.Entry(row2, textvariable=self.output_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row2, text="Browse...", style="Secondary.TButton",
                   command=self._browse_output).pack(side="left", padx=(8, 0))

        self.embed_button = ttk.Button(left, text="Encrypt & Embed Message",
                                        command=self._run_embed_thread)
        self.embed_button.pack(fill="x", pady=(4, 0))

        self.progress = ttk.Progressbar(left, mode="indeterminate")
        # progress bar is packed/unpacked dynamically during operation

        # --- Right column: preview ---
        ttk.Label(right, text="Preview", style="Panel.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.preview_label = ttk.Label(right, text="No image selected", style="Panel.TLabel",
                                        anchor="center", width=32)
        self.preview_label.pack(pady=12, fill="both", expand=True)

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            title="Save stego image as",
            defaultextension=".png",
            filetypes=[("PNG images", "*.png")],
        )
        if path:
            self.output_path.set(path)

    def _refresh_capacity(self):
        path = self.image_path.get()
        if not path or not os.path.isfile(path):
            self.capacity_label.configure(text="Select an image to see capacity.")
            return
        try:
            img = Image.open(path)
            capacity = get_image_capacity_bytes(img)
            self.capacity_label.configure(
                text=f"Capacity: ~{capacity:,} bytes ({img.size[0]}x{img.size[1]} px)")
        except Exception:
            self.capacity_label.configure(text="Could not read image.")

    def _run_embed_thread(self):
        image_path = self.image_path.get().strip()
        message = self.message_text.get("1.0", "end").rstrip("\n")
        password = self.password.get()
        output_path = self.output_path.get().strip()

        if not image_path:
            messagebox.showwarning(APP_TITLE, "Please select a cover image.")
            return
        if not message:
            messagebox.showwarning(APP_TITLE, "Please enter a message to hide.")
            return
        if not password:
            messagebox.showwarning(APP_TITLE, "Please enter a password.")
            return
        if not output_path:
            messagebox.showwarning(APP_TITLE, "Please choose where to save the stego image.")
            return

        self.embed_button.configure(state="disabled")
        self.progress.pack(fill="x", pady=(10, 0))
        self.progress.start(12)
        self.set_status("Encrypting and embedding...")

        thread = threading.Thread(
            target=self._do_embed, args=(image_path, message, password, output_path), daemon=True
        )
        thread.start()

    def _do_embed(self, image_path, message, password, output_path):
        try:
            if not os.path.isfile(image_path):
                raise FileNotFoundError(f"Cover image not found: '{image_path}'")
            image = Image.open(image_path)

            encrypted_blob = encrypt_message(message.encode("utf-8"), password)
            stego_image = embed_data_in_image(image, encrypted_blob)

            if not output_path.lower().endswith(".png"):
                output_path += ".png"
            stego_image.save(output_path, format="PNG")

            self.after(0, self._embed_success, output_path)
        except InsufficientCapacityError as e:
            self.after(0, self._embed_failure, "Image Too Small", str(e))
        except FileNotFoundError as e:
            self.after(0, self._embed_failure, "File Not Found", str(e))
        except StegArmorError as e:
            self.after(0, self._embed_failure, "StegArmor Error", str(e))
        except Exception as e:
            self.after(0, self._embed_failure, "Unexpected Error", str(e))

    def _embed_success(self, output_path):
        self.progress.stop()
        self.progress.pack_forget()
        self.embed_button.configure(state="normal")
        self.set_status(f"Success: stego image saved to {output_path}")
        messagebox.showinfo(APP_TITLE, f"Message encrypted and hidden successfully.\n\n"
                                        f"Saved to:\n{output_path}")

    def _embed_failure(self, title, detail):
        self.progress.stop()
        self.progress.pack_forget()
        self.embed_button.configure(state="normal")
        self.set_status(f"Failed: {detail}", is_error=True)
        messagebox.showerror(f"{APP_TITLE} - {title}", detail)


class ExtractTab(BaseTab):
    def __init__(self, parent):
        super().__init__(parent)
        self._build()

    def _build(self):
        left = ttk.Frame(self)
        left.pack(side="left", fill="both", expand=True, padx=(0, 16))
        right = ttk.Frame(self, style="Panel.TFrame", padding=12)
        right.pack(side="right", fill="y")

        ttk.Label(left, text="1. Stego Image (PNG)").pack(anchor="w", pady=(0, 4))
        row1 = ttk.Frame(left)
        row1.pack(fill="x", pady=(0, 12))
        ttk.Entry(row1, textvariable=self.image_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row1, text="Browse...", style="Secondary.TButton",
                   command=lambda: self.browse_image(self.image_path, self.preview_label)
                   ).pack(side="left", padx=(8, 0))

        ttk.Label(left, text="2. Password").pack(anchor="w", pady=(0, 4))
        pw_row = ttk.Frame(left)
        pw_row.pack(fill="x", pady=(0, 12))
        pw_entry = ttk.Entry(pw_row, textvariable=self.password, show="*")
        pw_entry.pack(side="left", fill="x", expand=True)
        self.show_password_toggle(pw_entry, self.password, pw_row).pack(side="left", padx=(8, 0))

        self.extract_button = ttk.Button(left, text="Extract & Decrypt Message",
                                          command=self._run_extract_thread)
        self.extract_button.pack(fill="x", pady=(4, 12))

        self.progress = ttk.Progressbar(left, mode="indeterminate")

        ttk.Label(left, text="Recovered Message").pack(anchor="w", pady=(4, 4))
        self.result_text = tk.Text(left, height=8, bg="#33334a", fg=TEXT_COLOR,
                                    insertbackground=TEXT_COLOR, relief="flat", padx=8, pady=8,
                                    state="disabled")
        self.result_text.pack(fill="both", expand=True)

        copy_row = ttk.Frame(left)
        copy_row.pack(fill="x", pady=(8, 0))
        ttk.Button(copy_row, text="Copy to Clipboard", style="Secondary.TButton",
                   command=self._copy_result).pack(side="left")
        ttk.Button(copy_row, text="Save to File...", style="Secondary.TButton",
                   command=self._save_result).pack(side="left", padx=(8, 0))

        ttk.Label(right, text="Preview", style="Panel.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.preview_label = ttk.Label(right, text="No image selected", style="Panel.TLabel",
                                        anchor="center", width=32)
        self.preview_label.pack(pady=12, fill="both", expand=True)

    def _run_extract_thread(self):
        image_path = self.image_path.get().strip()
        password = self.password.get()

        if not image_path:
            messagebox.showwarning(APP_TITLE, "Please select a stego image.")
            return
        if not password:
            messagebox.showwarning(APP_TITLE, "Please enter the password.")
            return

        self.extract_button.configure(state="disabled")
        self.progress.pack(fill="x", pady=(0, 8), before=self.result_text)
        self.progress.start(12)
        self.set_status("Extracting and decrypting...")
        self._set_result_text("")

        thread = threading.Thread(target=self._do_extract, args=(image_path, password), daemon=True)
        thread.start()

    def _do_extract(self, image_path, password):
        try:
            if not os.path.isfile(image_path):
                raise FileNotFoundError(f"Stego image not found: '{image_path}'")
            image = Image.open(image_path)

            encrypted_blob = extract_data_from_image(image)
            plaintext = decrypt_message(encrypted_blob, password)

            try:
                decoded = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                decoded = "[Binary data recovered -- not valid UTF-8 text. Use 'Save to File...' to save raw bytes.]"

            self.after(0, self._extract_success, decoded)
        except NoHiddenDataError as e:
            self.after(0, self._extract_failure, "No Hidden Data Found", str(e))
        except InvalidPasswordError as e:
            self.after(0, self._extract_failure, "Wrong Password", str(e))
        except FileNotFoundError as e:
            self.after(0, self._extract_failure, "File Not Found", str(e))
        except StegArmorError as e:
            self.after(0, self._extract_failure, "StegArmor Error", str(e))
        except Exception as e:
            self.after(0, self._extract_failure, "Unexpected Error", str(e))

    def _extract_success(self, message):
        self.progress.stop()
        self.progress.pack_forget()
        self.extract_button.configure(state="normal")
        self.set_status("Message extracted and decrypted successfully.")
        self._set_result_text(message)

    def _extract_failure(self, title, detail):
        self.progress.stop()
        self.progress.pack_forget()
        self.extract_button.configure(state="normal")
        self.set_status(f"Failed: {detail}", is_error=True)
        messagebox.showerror(f"{APP_TITLE} - {title}", detail)

    def _set_result_text(self, text):
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.configure(state="disabled")

    def _copy_result(self):
        text = self.result_text.get("1.0", "end").rstrip("\n")
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.set_status("Copied to clipboard.")

    def _save_result(self):
        text = self.result_text.get("1.0", "end").rstrip("\n")
        if not text:
            messagebox.showwarning(APP_TITLE, "There is no recovered message to save yet.")
            return
        path = filedialog.asksaveasfilename(title="Save recovered message",
                                             defaultextension=".txt",
                                             filetypes=[("Text file", "*.txt"), ("All files", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.set_status(f"Saved recovered message to {path}")


def main():
    app = StegArmorGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
