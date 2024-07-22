import sys
import os
import subprocess

def text_to_clipboard(text):
    if sys.platform.startswith("linux"):
        if "WAYLAND_DISPLAY" in os.environ:
            try:
                subprocess.run(["wl-copy"], input=text.encode(), check=True)
            except FileNotFoundError:
                print("wl-copy not found, is it installed?", file=sys.stderr)
                exit(0)
        elif "DISPLAY" in os.environ:
            try:
                p = subprocess.Popen(["xsel", "-bi"], stdin=subprocess.PIPE)
                p.communicate(input=text.encode())
            except FileNotFoundError:
                print("xsel not found, is it installed?", file=sys.stderr)
                exit(0)
    elif sys.platform.startswith("darwin"):
        subprocess.run(["pbcopy"], input=text.encode(), check=True)
    elif sys.platform.startswith("win"):
        try:
            import pyperclip
            pyperclip.copy(text)
        except ImportError:
            print("pyperclip not found, please install it", file=sys.stderr)
            exit(0)