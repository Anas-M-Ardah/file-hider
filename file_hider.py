"""
File Hider - a small desktop utility to hide and unhide files/folders on Windows.

It toggles the standard Windows "hidden" file attribute (the same setting you get via
right-click -> Properties -> Hidden). This is NOT security or encryption: anyone can reveal
hidden files by enabling Explorer's "Show hidden files" option. It is meant for casual
tidying/decluttering only.

The app keeps a plain-text JSON index (hidden_index.json, stored next to the app) of what it
has hidden, so that hidden items stay findable and can be restored later - once an item is
hidden it may no longer appear in Explorer's default view.
"""

import base64
import ctypes
import io
import json
import os
import shutil
import sys
import zipfile
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- Windows file-attribute constants / helpers ---------------------------------
FILE_ATTRIBUTE_HIDDEN = 0x02
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


def _app_dir():
    """Directory the app lives in (handles both script and PyInstaller exe)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


INDEX_PATH = os.path.join(_app_dir(), "hidden_index.json")


def get_attributes(path):
    """Return current attribute bitmask for path, or None if it can't be read."""
    attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if attrs == INVALID_FILE_ATTRIBUTES:
        return None
    return attrs


def set_hidden(path, hidden=True):
    """Set or clear the 'hidden' attribute on path. Returns True on success.

    We read the existing attributes and flip only the HIDDEN bit, so we never
    disturb other attributes (read-only, archive, etc.).
    """
    attrs = get_attributes(path)
    if attrs is None:
        return False
    if hidden:
        new_attrs = attrs | FILE_ATTRIBUTE_HIDDEN
    else:
        new_attrs = attrs & ~FILE_ATTRIBUTE_HIDDEN
    ok = ctypes.windll.kernel32.SetFileAttributesW(str(path), new_attrs)
    return bool(ok)


def is_hidden(path):
    attrs = get_attributes(path)
    if attrs is None:
        return False
    return bool(attrs & FILE_ATTRIBUTE_HIDDEN)


# --- Encryption ("lock"/"unlock") ----------------------------------------------
# Locking a file actually protects its contents: the bytes are encrypted with a key
# derived from the user's password, so even someone who knows the exact path cannot read
# the data without the password. This is real protection, unlike the hidden attribute.
#
# A locked item is written as "<original>.locked" (JSON holding the salt + ciphertext),
# and the original file/folder is removed. Unlocking reverses it.
#
# WARNING: encryption is only as safe as the password. If the password is forgotten, the
# data is unrecoverable - there is no backdoor.

LOCK_EXT = ".locked"
_SCRYPT_N = 2 ** 14  # CPU/memory cost factor for key derivation


def _derive_key(password, salt):
    """Derive a 32-byte Fernet key from password + salt using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=8, p=1)
    raw = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _zip_dir_to_bytes(folder):
    """Zip a directory (recursively) into an in-memory bytes object."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(folder):
            for name in files:
                full = os.path.join(root, name)
                arc = os.path.relpath(full, folder)
                zf.write(full, arc)
    return buf.getvalue()


def _unzip_bytes_to_dir(data, dest):
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        zf.extractall(dest)


def lock_path(path, password):
    """Encrypt a file or folder. Returns the created .locked path.

    Raises FileExistsError if a matching .locked already exists.
    """
    path = os.path.abspath(path)
    locked_path = path + LOCK_EXT
    if os.path.exists(locked_path):
        raise FileExistsError(locked_path)

    is_dir = os.path.isdir(path)
    plaintext = _zip_dir_to_bytes(path) if is_dir else open(path, "rb").read()

    salt = os.urandom(16)
    token = Fernet(_derive_key(password, salt)).encrypt(plaintext)

    payload = {
        "version": 1,
        "is_dir": is_dir,
        "orig_name": os.path.basename(path),
        "salt": base64.b64encode(salt).decode("ascii"),
        "token": base64.b64encode(token).decode("ascii"),
        "locked_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    # Write the locked file first; only remove the original once it is safely on disk.
    with open(locked_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)

    if is_dir:
        shutil.rmtree(path)
    else:
        os.remove(path)
    return locked_path


def unlock_path(locked_path, password):
    """Decrypt a .locked file, restoring the original file/folder. Returns its path.

    Raises InvalidToken on a wrong password or corrupted data.
    """
    locked_path = os.path.abspath(locked_path)
    with open(locked_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    salt = base64.b64decode(payload["salt"])
    token = base64.b64decode(payload["token"])
    plaintext = Fernet(_derive_key(password, salt)).decrypt(token)  # raises InvalidToken

    dest_dir = os.path.dirname(locked_path)
    orig = os.path.join(dest_dir, payload["orig_name"])
    if os.path.exists(orig):
        raise FileExistsError(orig)

    if payload.get("is_dir"):
        os.makedirs(orig, exist_ok=False)
        _unzip_bytes_to_dir(plaintext, orig)
    else:
        with open(orig, "wb") as f:
            f.write(plaintext)

    os.remove(locked_path)
    return orig


# --- Index (plain JSON) persistence ---------------------------------------------
def load_index():
    """Load the list of hidden entries. Returns a list of dicts {path, hidden_at}."""
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return []


def save_index(entries):
    try:
        with open(INDEX_PATH, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2)
    except OSError as e:
        messagebox.showerror("File Hider", f"Could not save index:\n{e}")


# --- GUI ------------------------------------------------------------------------
class FileHiderApp:
    def __init__(self, root):
        self.root = root
        self.entries = load_index()

        root.title("File Hider")
        root.geometry("640x420")
        root.minsize(520, 340)

        # Honest notice: which action actually protects data.
        notice = (
            "Hide/Unhide only toggles the Windows 'hidden' flag - the file is still readable "
            "if you know the path. Lock encrypts the contents with a password (real "
            "protection). WARNING: if you forget a Lock password, the data is unrecoverable."
        )
        ttk.Label(root, text=notice, foreground="#8a5a00", wraplength=600,
                  justify="left").pack(fill="x", padx=10, pady=(10, 4))

        # Path entry row: type or browse to a file/folder path.
        ttk.Label(root, text="File or folder path:").pack(
            fill="x", padx=10, pady=(6, 0), anchor="w")
        path_row = ttk.Frame(root)
        path_row.pack(fill="x", padx=10, pady=(0, 2))
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(path_row, textvariable=self.path_var)
        self.path_entry.pack(side="left", fill="x", expand=True)
        self.path_entry.bind("<Return>", lambda e: self.hide_path())
        ttk.Button(path_row, text="Browse File...",
                   command=self.browse_file).pack(side="left", padx=(6, 0))
        ttk.Button(path_row, text="Browse Folder...",
                   command=self.browse_folder).pack(side="left", padx=(6, 0))

        # Action row: choose what to do with the entered path.
        action_row = ttk.Frame(root)
        action_row.pack(fill="x", padx=10, pady=4)
        ttk.Button(action_row, text="Lock (encrypt)", command=self.lock_entry).pack(side="left")
        ttk.Button(action_row, text="Unlock (decrypt)", command=self.unlock_entry).pack(side="left", padx=(6, 0))
        ttk.Separator(action_row, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(action_row, text="Hide", command=self.hide_path).pack(side="left")
        ttk.Button(action_row, text="Unhide", command=self.unhide_path).pack(side="left", padx=(6, 0))

        # Second action row for list operations.
        list_row = ttk.Frame(root)
        list_row.pack(fill="x", padx=10, pady=(0, 2))
        ttk.Button(list_row, text="Unhide Selected", command=self.unhide_selected).pack(side="left")
        ttk.Button(list_row, text="Unhide All", command=self.unhide_all).pack(side="left", padx=(6, 0))
        ttk.Button(list_row, text="Refresh", command=self.refresh).pack(side="right")

        # List of hidden items.
        frame = ttk.Frame(root)
        frame.pack(fill="both", expand=True, padx=10, pady=(4, 4))
        self.listbox = tk.Listbox(frame, selectmode=tk.EXTENDED, activestyle="none")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Status bar.
        self.status = tk.StringVar(value="Ready.")
        ttk.Label(root, textvariable=self.status, relief="sunken", anchor="w").pack(
            fill="x", side="bottom")

        self.reconcile_and_render()

    # -- helpers --
    def set_status(self, msg):
        self.status.set(msg)

    def reconcile_and_render(self):
        """Drop entries whose paths no longer exist, then redraw the list."""
        kept = [e for e in self.entries if os.path.exists(e.get("path", ""))]
        if len(kept) != len(self.entries):
            self.entries = kept
            save_index(self.entries)
        self.render()

    def render(self):
        self.listbox.delete(0, tk.END)
        for e in self.entries:
            when = e.get("hidden_at", "")
            flag = "" if is_hidden(e["path"]) else "  [not hidden!]"
            self.listbox.insert(tk.END, f'{e["path"]}    ({when}){flag}')

    def _add_entry(self, path):
        path = os.path.abspath(path)
        # Avoid duplicates.
        for e in self.entries:
            if os.path.normcase(e["path"]) == os.path.normcase(path):
                return
        self.entries.append({
            "path": path,
            "hidden_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        })

    def _hide_paths(self, paths):
        hidden, failed = 0, []
        for p in paths:
            if set_hidden(p, True):
                self._add_entry(p)
                hidden += 1
            else:
                failed.append(p)
        save_index(self.entries)
        self.render()
        msg = f"Hidden {hidden} item(s)."
        if failed:
            msg += f" Failed: {len(failed)}."
        self.set_status(msg)
        if failed:
            messagebox.showwarning("File Hider",
                                   "Could not hide:\n" + "\n".join(failed))

    # -- actions --
    def browse_file(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.path_var.set(path)

    def browse_folder(self):
        path = filedialog.askdirectory(title="Select a folder")
        if path:
            self.path_var.set(path)

    def _current_path(self):
        """Validated path from the entry box, or None (with a status message)."""
        path = self.path_var.get().strip().strip('"')
        if not path:
            self.set_status("Enter or browse to a file/folder path first.")
            return None
        if not os.path.exists(path):
            self.set_status("Path does not exist.")
            messagebox.showwarning("File Hider", f"Path does not exist:\n{path}")
            return None
        return path

    def hide_path(self):
        path = self._current_path()
        if path:
            self._hide_paths([path])

    def _ask_password(self, title, confirm=False):
        """Prompt for a password. If confirm=True, ask twice and require a match."""
        pw = simpledialog.askstring(title, "Password:", show="*", parent=self.root)
        if pw is None:
            return None
        if not pw:
            messagebox.showwarning("File Hider", "Password cannot be empty.")
            return None
        if confirm:
            again = simpledialog.askstring(title, "Confirm password:", show="*",
                                           parent=self.root)
            if again is None:
                return None
            if pw != again:
                messagebox.showwarning("File Hider", "Passwords did not match.")
                return None
        return pw

    def lock_entry(self):
        path = self._current_path()
        if not path:
            return
        if path.endswith(LOCK_EXT):
            messagebox.showinfo("File Hider", "That item is already locked.")
            return
        kind = "folder" if os.path.isdir(path) else "file"
        if not messagebox.askyesno(
                "File Hider",
                f"Lock (encrypt) this {kind}?\n\n{path}\n\n"
                "The original will be replaced by an encrypted .locked file.\n"
                "If you forget the password, the data CANNOT be recovered."):
            return
        pw = self._ask_password("Set lock password", confirm=True)
        if not pw:
            return
        try:
            locked = lock_path(path, pw)
        except FileExistsError as e:
            messagebox.showwarning("File Hider", f"A locked file already exists:\n{e}")
            return
        except (OSError, PermissionError) as e:
            messagebox.showerror("File Hider", f"Could not lock:\n{e}")
            return
        self.path_var.set(locked)
        self.render()
        self.set_status(f"Locked -> {locked}")

    def unlock_entry(self):
        path = self._current_path()
        if not path:
            return
        if not path.endswith(LOCK_EXT):
            messagebox.showinfo(
                "File Hider",
                f"Select a {LOCK_EXT} file to unlock (the one created by Lock).")
            return
        pw = self._ask_password("Enter lock password")
        if not pw:
            return
        try:
            restored = unlock_path(path, pw)
        except InvalidToken:
            messagebox.showerror("File Hider",
                                 "Wrong password, or the locked file is corrupted.")
            return
        except FileExistsError as e:
            messagebox.showwarning(
                "File Hider",
                f"Cannot restore - a file/folder with that name already exists:\n{e}")
            return
        except (OSError, PermissionError, KeyError, ValueError) as e:
            messagebox.showerror("File Hider", f"Could not unlock:\n{e}")
            return
        self.path_var.set(restored)
        self.render()
        self.set_status(f"Unlocked -> {restored}")

    def unhide_path(self):
        path = self._current_path()
        if not path:
            return
        if set_hidden(path, False):
            path_n = os.path.normcase(os.path.abspath(path))
            self.entries = [e for e in self.entries
                            if os.path.normcase(e["path"]) != path_n]
            save_index(self.entries)
            self.render()
            self.set_status(f"Unhid: {path}")
        else:
            self.set_status("Could not unhide that path.")
            messagebox.showwarning("File Hider", f"Could not unhide:\n{path}")

    def _selected_entries(self):
        return [self.entries[i] for i in self.listbox.curselection()]

    def unhide_selected(self):
        sel = self._selected_entries()
        if not sel:
            self.set_status("Nothing selected.")
            return
        self._unhide(sel)

    def unhide_all(self):
        if not self.entries:
            self.set_status("List is empty.")
            return
        if not messagebox.askyesno("File Hider",
                                   f"Unhide all {len(self.entries)} item(s)?"):
            return
        self._unhide(list(self.entries))

    def _unhide(self, targets):
        done, failed = 0, []
        remaining = list(self.entries)
        for e in targets:
            if set_hidden(e["path"], False):
                done += 1
                remaining = [r for r in remaining
                             if os.path.normcase(r["path"]) != os.path.normcase(e["path"])]
            else:
                failed.append(e["path"])
        self.entries = remaining
        save_index(self.entries)
        self.render()
        msg = f"Unhid {done} item(s)."
        if failed:
            msg += f" Failed: {len(failed)}."
        self.set_status(msg)
        if failed:
            messagebox.showwarning("File Hider",
                                   "Could not unhide:\n" + "\n".join(failed))

    def refresh(self):
        self.entries = load_index()
        self.reconcile_and_render()
        self.set_status("Refreshed.")


def main():
    if os.name != "nt":
        # The hidden-attribute mechanism here is Windows-specific.
        print("This tool targets Windows (uses the Windows hidden-file attribute).")
    root = tk.Tk()
    FileHiderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
