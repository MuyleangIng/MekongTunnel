"""
Locate the mekong binary on the current system.
No external dependencies — stdlib only.
"""

import os
import shutil
import sys


def find_mekong() -> 'str | None':
    """
    Search for the mekong binary in common locations.

    Order:
      1. shutil.which('mekong')  — skipped if the path contains 'mekong_tunnel'
         (that would resolve to this package's own console-script wrapper)
      2. ~/.local/bin/mekong
      3. /usr/local/bin/mekong
      4. /usr/bin/mekong
      5. Windows extras: same paths with .exe + %USERPROFILE%\\AppData\\Local\\mekong.exe

    Returns the absolute path string, or None if not found.
    """
    is_windows = sys.platform.startswith('win')
    suffixes = ['.exe', ''] if is_windows else ['']

    # --- 1. PATH lookup via shutil.which ---
    for suffix in suffixes:
        candidate = shutil.which('mekong' + suffix)
        if candidate and 'mekong_tunnel' not in candidate:
            return candidate

    # --- 2-4. Well-known fixed paths ---
    home = os.path.expanduser('~')

    # /usr/local/bin first — macOS default install location (always in VS Code PATH)
    fixed_paths = [
        '/usr/local/bin/mekong',
        os.path.join(home, '.local', 'bin', 'mekong'),
        os.path.join(home, 'bin', 'mekong'),
        '/usr/bin/mekong',
        '/opt/homebrew/bin/mekong',
    ]

    if is_windows:
        local = os.environ.get('LOCALAPPDATA', os.path.join(home, 'AppData', 'Local'))
        userprofile = os.environ.get('USERPROFILE', home)
        fixed_paths += [
            os.path.join(local, 'Programs', 'mekong', 'mekong.exe'),
            os.path.join(local, 'mekong.exe'),
            os.path.join(home, '.local', 'bin', 'mekong.exe'),
            os.path.join(userprofile, 'AppData', 'Local', 'Programs', 'mekong', 'mekong.exe'),
        ]

    for path in fixed_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None
