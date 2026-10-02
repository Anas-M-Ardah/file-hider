# File Hider

A small Windows desktop utility (Python + Tkinter) to **hide and unhide files/folders** by
toggling the standard Windows "hidden" file attribute — the same setting as
right-click → **Properties → Hidden**.

## Two different actions — know the difference

| Action | What it does | Real protection? |
|--------|--------------|------------------|
| **Hide / Unhide** | Toggles the Windows *hidden* attribute. | **No.** Anyone can reveal it via **View → Show → Hidden items**, and the file still opens if you know its path. Casual tidying only. |
| **Lock / Unlock** | **Encrypts** the file/folder contents with a password (AES, via the `cryptography` library). | **Yes.** Even with the exact path, the data is unreadable without the password. |

### ⚠️ Lock warnings

- **If you forget the Lock password, the data is gone — permanently.** There is no backdoor
  and no recovery.
- Locking **replaces** the original file/folder with an encrypted `<name>.locked` file. To get
  your data back you must Unlock that `.locked` file with the same password.
- Keep a backup of important data before locking it.

## Quick start (no Python needed)

Double-click **`dist\FileHider.exe`**. In the window:

1. Type a file/folder path into the **File or folder path** box (or use **Browse File… /
   Browse Folder…** to fill it in).
2. Choose an action:
   - **Lock (encrypt)** — set a password; the item becomes an unreadable `.locked` file.
   - **Unlock (decrypt)** — point at the `.locked` file, enter the password to restore it.
   - **Hide / Unhide** — toggle the (non-protective) hidden attribute.

`FileHider.exe` creates `hidden_index.json` next to itself, so keep the exe in a writable
location.

## Features

- **Path box + Hide / Unhide** — enter any path and choose the action. (Press Enter in the box
  to Hide.)
- **Browse File… / Browse Folder…** — fill the path box via a picker.
- **Unhide Selected** / **Unhide All** — clear the hidden attribute on tracked items and
  restore visibility.
- A tracked list (`hidden_index.json`, stored next to the app) of everything the app has
  hidden, so hidden items stay findable and restorable. The list auto-reconciles on startup
  (entries whose paths no longer exist are dropped), and flags any item that is no longer
  actually hidden.

Only the *hidden* attribute is used — the *system* attribute is deliberately not set, so your
files keep behaving normally.

## Requirements

- Windows (uses the Windows file-attribute API via `ctypes`).
- Python 3.8+ with Tkinter (bundled with the standard Windows Python installer).

## Run from source

```powershell
python file_hider.py
```

## Package into a standalone .exe (PyInstaller)

```powershell
pip install pyinstaller
pyinstaller --onefile --windowed file_hider.py
```

The executable is produced at `dist\file_hider.exe`. Note that `hidden_index.json` is created
next to the exe at runtime, so keep the exe somewhere writable.

## Usage notes

- To see hidden items in Explorer yourself, enable **View → Show → Hidden items**.
- Hiding a **folder** hides the folder entry; its contents keep their own attributes.
- If you move or delete the app, the `hidden_index.json` list is what remembers hidden paths —
  keep it alongside the app if you want to manage previously hidden items.
