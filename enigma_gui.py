#!/usr/bin/env python3
"""
Enigma Cracker GUI — Tkinter wrapper for enigma_cracker.c

Features:
  - Paste uncracked Enigma ciphertext
  - Select M3 or M4 mode
  - Crack button: compiles C binary if needed, runs it, captures output
  - Results: decrypted plaintext, settings found, elapsed time
  - Progress indicator while cracking (reads stderr PROGRESS: lines)
  - Save Results button to export to text file
  - Cross-platform: Linux (gcc) and Windows 11 (MinGW gcc)

Usage:
  python3 enigma_gui.py

Author: Hermes Agent
"""

import os
import sys
import json
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

# ─── Constants ───

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
C_SOURCE = os.path.join(SCRIPT_DIR, "enigma_cracker.c")
BINARY_NAME = "enigma_cracker" if sys.platform != "win32" else "enigma_cracker.exe"
BINARY_PATH = os.path.join(SCRIPT_DIR, BINARY_NAME)


# ─── Compiler detection ───

def find_compiler():
    """Find a C compiler. Returns the command name or None."""
    candidates = ["gcc", "cc", "clang", "mingw32-gcc", "x86_64-w64-mingw32-gcc"]
    for cc in candidates:
        try:
            r = subprocess.run(
                [cc, "--version"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                return cc
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def compile_binary():
    """Compile the C binary. Returns (success, message)."""
    cc = find_compiler()
    if not cc:
        return False, (
            "No C compiler found.\n\n"
            "Linux: install gcc (e.g. `sudo apt install gcc`)\n"
            "Windows: install MinGW (https://www.mingw-w64.org/)\n"
            "  or MSYS2 with `pacman -S mingw-w64-x86_64-gcc`"
        )

    if not os.path.exists(C_SOURCE):
        return False, f"C source file not found:\n{C_SOURCE}"

    cmd = [cc, "-O3", "-fopenmp", "-o", BINARY_PATH, C_SOURCE, "-lm"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            return True, f"Compiled successfully with {cc}"
        else:
            return False, f"Compilation failed:\n{r.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out (>60s)"
    except Exception as e:
        return False, f"Compilation error: {e}"


def ensure_binary():
    """Ensure the C binary exists and is up-to-date. Returns (success, message)."""
    # Check if binary exists and is newer than source
    if os.path.exists(BINARY_PATH):
        bin_mtime = os.path.getmtime(BINARY_PATH)
        src_mtime = os.path.getmtime(C_SOURCE) if os.path.exists(C_SOURCE) else 0
        if bin_mtime >= src_mtime:
            return True, "Binary is up-to-date"

    # Need to compile
    return compile_binary()


# ─── Main GUI ───

class EnigmaCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enigma Cracker — M3/M4 Brute-Force")
        self.root.geometry("900x750")
        self.root.minsize(700, 600)

        # State
        self.last_result = None
        self.cracking = False
        self.process = None

        # Build UI
        self._build_ui()

        # Check binary on startup
        self.root.after(100, self._startup_check)

    def _build_ui(self):
        # ─── Top frame: Input ───
        input_frame = ttk.LabelFrame(self.root, text="Input", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        # Ciphertext label
        ttk.Label(input_frame, text="Ciphertext (A-Z only, spaces/spaces stripped):").pack(anchor=tk.W)

        # Ciphertext text area with scroll
        ct_container = ttk.Frame(input_frame)
        ct_container.pack(fill=tk.X, pady=(4, 8))

        self.ct_text = tk.Text(ct_container, height=4, font=("Courier", 11), wrap=tk.NONE)
        ct_scroll_x = ttk.Scrollbar(ct_container, orient=tk.HORIZONTAL, command=self.ct_text.xview)
        ct_scroll_y = ttk.Scrollbar(ct_container, orient=tk.VERTICAL, command=self.ct_text.yview)
        self.ct_text.configure(xscrollcommand=ct_scroll_x.set, yscrollcommand=ct_scroll_y.set)

        self.ct_text.grid(row=0, column=0, sticky="nsew")
        ct_scroll_y.grid(row=0, column=1, sticky="ns")
        ct_scroll_x.grid(row=1, column=0, sticky="ew")
        ct_container.grid_rowconfigure(0, weight=1)
        ct_container.grid_columnconfigure(0, weight=1)

        # Mode selector + buttons row
        ctrl_frame = ttk.Frame(input_frame)
        ctrl_frame.pack(fill=tk.X, pady=(4, 0))

        ttk.Label(ctrl_frame, text="Mode:").pack(side=tk.LEFT, padx=(0, 4))
        self.mode_var = tk.StringVar(value="M3")
        mode_m3 = ttk.Radiobutton(ctrl_frame, text="M3 (Army/Air Force, 3-rotor)", variable=self.mode_var, value="M3")
        mode_m3.pack(side=tk.LEFT, padx=(0, 10))
        mode_m4 = ttk.Radiobutton(ctrl_frame, text="M4 (Naval, 4-rotor)", variable=self.mode_var, value="M4")
        mode_m4.pack(side=tk.LEFT, padx=(0, 20))

        self.crack_btn = ttk.Button(ctrl_frame, text="🔓  Crack", command=self.on_crack)
        self.crack_btn.pack(side=tk.LEFT, padx=4)

        self.clear_btn = ttk.Button(ctrl_frame, text="Clear", command=self.on_clear)
        self.clear_btn.pack(side=tk.LEFT, padx=4)

        # ─── Progress frame ───
        self.progress_frame = ttk.Frame(self.root)
        self.progress_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

        self.progress_label = ttk.Label(self.progress_frame, text="Ready")
        self.progress_label.pack(anchor=tk.W)

        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='determinate', maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(2, 0))

        # ─── Results frame ───
        results_frame = ttk.LabelFrame(self.root, text="Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 5))

        # Settings summary (top)
        settings_frame = ttk.Frame(results_frame)
        settings_frame.pack(fill=tk.X, pady=(0, 6))

        self.settings_label = ttk.Label(settings_frame, text="Settings: (not cracked yet)", font=("Courier", 10),
                                         justify=tk.LEFT)
        self.settings_label.pack(anchor=tk.W)

        self.time_label = ttk.Label(settings_frame, text="Elapsed: —", font=("Courier", 10))
        self.time_label.pack(anchor=tk.W, pady=(2, 0))

        # Plaintext area
        ttk.Label(results_frame, text="Decrypted Plaintext:").pack(anchor=tk.W)

        pt_container = ttk.Frame(results_frame)
        pt_container.pack(fill=tk.BOTH, expand=True, pady=(4, 6))

        self.pt_text = tk.Text(pt_container, font=("Courier", 11), wrap=tk.WORD, state=tk.DISABLED)
        pt_scroll = ttk.Scrollbar(pt_container, orient=tk.VERTICAL, command=self.pt_text.yview)
        self.pt_text.configure(yscrollcommand=pt_scroll.set)
        self.pt_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pt_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Raw output area (collapsible / at bottom)
        ttk.Label(results_frame, text="Raw Output:").pack(anchor=tk.W)
        raw_container = ttk.Frame(results_frame)
        raw_container.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        self.raw_text = tk.Text(raw_container, font=("Courier", 9), wrap=tk.WORD, height=6, state=tk.DISABLED)
        raw_scroll = ttk.Scrollbar(raw_container, orient=tk.VERTICAL, command=self.raw_text.yview)
        self.raw_text.configure(yscrollcommand=raw_scroll.set)
        self.raw_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        raw_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # ─── Bottom frame: action buttons ───
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.save_btn = ttk.Button(bottom_frame, text="💾  Save Results", command=self.on_save, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=4)

        self.recompile_btn = ttk.Button(bottom_frame, text="🔄  Recompile Binary", command=self.on_recompile)
        self.recompile_btn.pack(side=tk.LEFT, padx=4)

        self.status_label = ttk.Label(bottom_frame, text="", font=("Courier", 9))
        self.status_label.pack(side=tk.RIGHT)

        # ─── Menu bar ───
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Save Results...", command=self.on_save, accelerator="Ctrl+S")
        filemenu.add_command(label="Recompile Binary", command=self.on_recompile)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.on_about)
        helpmenu.add_command(label="Usage Guide", command=self.on_usage)
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.root.configure(menu=menubar)

        # Keyboard shortcuts
        self.root.bind("<Control-s>", lambda e: self.on_save())

    # ─── Startup ───

    def _startup_check(self):
        """Check if binary exists; compile if needed."""
        ok, msg = ensure_binary()
        self.status_label.config(text=msg)
        if not ok:
            messagebox.showwarning("Binary Not Ready", msg)
            self.status_label.config(text="⚠ Binary not ready — click Recompile")

    # ─── Actions ───

    def on_crack(self):
        if self.cracking:
            return

        ct_raw = self.ct_text.get("1.0", tk.END).strip()
        if not ct_raw:
            messagebox.showwarning("No Input", "Please paste ciphertext first.")
            return

        # Sanitize: uppercase, strip non-alpha
        ct = ''.join(c for c in ct_raw.upper() if 'A' <= c <= 'Z')
        if len(ct) < 10:
            if not messagebox.askyesno("Short Ciphertext",
                                        f"Ciphertext is only {len(ct)} chars.\n"
                                        "Cracking short messages is unreliable.\nContinue?"):
                return

        mode = self.mode_var.get()
        self.cracking = True
        self.crack_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Checking binary...")

        # Clear previous results
        self.pt_text.config(state=tk.NORMAL)
        self.pt_text.delete("1.0", tk.END)
        self.pt_text.config(state=tk.DISABLED)
        self.raw_text.config(state=tk.NORMAL)
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.config(state=tk.DISABLED)
        self.settings_label.config(text="Settings: (cracking...)")

        # Start cracking thread
        thread = threading.Thread(target=self._crack_thread, args=(ct, mode), daemon=True)
        thread.start()

    def _crack_thread(self, ct, mode):
        """Run the cracker in a background thread."""
        try:
            # Ensure binary
            ok, msg = ensure_binary()
            if not ok:
                self.root.after(0, self._crack_error, msg)
                return

            self.root.after(0, lambda: self.progress_label.config(text="Cracking... (this may take a while)"))

            # Build command: use JSON output for reliable parsing
            cmd = [BINARY_PATH, "--ct", ct, "--mode", mode, "--format", "json"]

            # Start process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Read stderr line by line for progress updates
            stderr_lines = []
            while True:
                line = self.process.stderr.readline()
                if not line and self.process.poll() is not None:
                    break
                if line:
                    stderr_lines.append(line)
                    line = line.strip()
                    if line.startswith("PROGRESS:"):
                        self.root.after(0, self._update_progress, line)

            # Get stdout (JSON)
            stdout_data = self.process.stdout.read()
            rc = self.process.wait()
            self.process = None

            if rc != 0:
                err_msg = ''.join(stderr_lines)
                self.root.after(0, self._crack_error, f"Binary exited with code {rc}:\n{err_msg}")
                return

            # Parse JSON
            try:
                result = json.loads(stdout_data)
                self.last_result = result
                self.root.after(0, self._crack_success, result, ''.join(stderr_lines))
            except json.JSONDecodeError as e:
                # Fall back: show raw output
                self.root.after(0, self._crack_error, f"JSON parse error: {e}\n\nRaw output:\n{stdout_data}")

        except FileNotFoundError:
            self.root.after(0, self._crack_error, f"Binary not found: {BINARY_PATH}")
        except Exception as e:
            self.root.after(0, self._crack_error, f"Error: {e}")

    def _update_progress(self, line):
        """Parse PROGRESS: lines from stderr and update the progress bar."""
        # Format: PROGRESS:phase:current:total
        parts = line.split(":")
        if len(parts) < 4:
            return
        phase = parts[1]
        try:
            current = int(parts[2])
            total = int(parts[3])
        except ValueError:
            return

        if total <= 0:
            # Phase done or indeterminate
            if parts[2] == "done":
                self.progress_bar['value'] = 100
                self.progress_label.config(text=f"Phase 1 complete — searching candidates...")
            return

        pct = min(100, (current / total) * 100)
        self.progress_bar['value'] = pct

        phase_names = {
            "phase1": "Phase 1: Rotor permutation search",
            "phase2": "Phase 2: Ring settings search",
            "phase3": "Phase 3: Plugboard hill climbing",
            "done": "Complete"
        }
        label = phase_names.get(phase, phase)
        if current == 0 and parts[2] != "done":
            self.progress_label.config(text=f"{label} (0/{total})...")
        elif parts[2] == "done":
            self.progress_label.config(text=f"{label}")
        else:
            self.progress_label.config(text=f"{label} ({current}/{total})")

    def _crack_success(self, result, stderr_raw):
        """Display cracking results in the GUI."""
        self.cracking = False
        self.crack_btn.config(state=tk.NORMAL)
        self.progress_bar['value'] = 100

        if not result.get("success", False):
            self.progress_label.config(text="❌ No solution found")
            self.settings_label.config(text="Settings: (no candidates found)")
            self.time_label.config(text=f"Elapsed: {result.get('elapsed_time', '?')}s")
            self.pt_text.config(state=tk.NORMAL)
            self.pt_text.insert(tk.END, "(No solution found — try different mode or longer ciphertext)")
            self.pt_text.config(state=tk.DISABLED)
            return

        # Settings
        mode = result.get("mode", "?")
        rotors = result.get("rotors", "?")
        reflector = result.get("reflector", "?")
        positions = result.get("positions", "?")
        rings = result.get("rings", "?")
        plugboard = result.get("plugboard", "(none)")
        german = result.get("german_score", 0)
        elapsed = result.get("elapsed_time", 0)
        configs = result.get("configs_tried", 0)
        plaintext = result.get("plaintext", "")

        settings_parts = []
        if mode == "M4":
            thin = result.get("thin_rotor", "?")
            thin_pos = result.get("thin_position", "?")
            thin_ring = result.get("thin_ring", "?")
            settings_parts.append(f"Mode: {mode}")
            settings_parts.append(f"Thin: {thin} @ {thin_pos} (ring {thin_ring})")
            settings_parts.append(f"Rotors: {rotors}")
            settings_parts.append(f"Reflector: {reflector}")
            settings_parts.append(f"Positions: {positions}")
            settings_parts.append(f"Rings: {rings}")
        else:
            settings_parts.append(f"Mode: {mode}")
            settings_parts.append(f"Rotors: {rotors}")
            settings_parts.append(f"Reflector: {reflector}")
            settings_parts.append(f"Positions: {positions}")
            settings_parts.append(f"Rings: {rings}")

        settings_text = "Settings: " + " | ".join(settings_parts)
        self.settings_label.config(text=settings_text)

        self.time_label.config(text=f"Elapsed: {elapsed:.2f}s  |  Configs: {configs:,}  |  German score: {german}")

        # Plaintext
        self.pt_text.config(state=tk.NORMAL)
        self.pt_text.delete("1.0", tk.END)
        self.pt_text.insert(tk.END, plaintext)
        self.pt_text.config(state=tk.DISABLED)

        # Raw output (stderr progress + reconstructed info)
        raw_lines = []
        raw_lines.append(f"=== Enigma Cracker Results ===")
        raw_lines.append(f"Mode: {mode}")
        raw_lines.append(f"Rotors: {rotors}")
        raw_lines.append(f"Reflector: {reflector}")
        raw_lines.append(f"Positions: {positions}")
        raw_lines.append(f"Rings: {rings}")
        if mode == "M4":
            raw_lines.append(f"Thin rotor: {result.get('thin_rotor','?')} @ {result.get('thin_position','?')}")
        raw_lines.append(f"Plugboard: {plugboard}")
        raw_lines.append(f"German score: {german}")
        raw_lines.append(f"Configs tried: {configs:,}")
        raw_lines.append(f"Elapsed: {elapsed:.2f}s")
        raw_lines.append(f"")
        raw_lines.append(f"Plaintext:")
        raw_lines.append(plaintext)
        raw_lines.append(f"")
        raw_lines.append(f"=== Progress log ===")
        raw_lines.append(stderr_raw.strip())

        self.raw_text.config(state=tk.NORMAL)
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert(tk.END, '\n'.join(raw_lines))
        self.raw_text.config(state=tk.DISABLED)

        self.progress_label.config(text=f"✅ Done in {elapsed:.2f}s — German score: {german}")
        self.save_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Crack complete")

    def _crack_error(self, msg):
        """Display an error."""
        self.cracking = False
        self.crack_btn.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        self.progress_label.config(text="❌ Error")
        self.status_label.config(text="Error")
        self.raw_text.config(state=tk.NORMAL)
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert(tk.END, str(msg))
        self.raw_text.config(state=tk.DISABLED)
        messagebox.showerror("Crack Error", str(msg))

    def on_clear(self):
        self.ct_text.delete("1.0", tk.END)
        self.pt_text.config(state=tk.NORMAL)
        self.pt_text.delete("1.0", tk.END)
        self.pt_text.config(state=tk.DISABLED)
        self.raw_text.config(state=tk.NORMAL)
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.config(state=tk.DISABLED)
        self.settings_label.config(text="Settings: (not cracked yet)")
        self.time_label.config(text="Elapsed: —")
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Ready")
        self.save_btn.config(state=tk.DISABLED)
        self.last_result = None

    def on_save(self):
        if not self.last_result and not self.raw_text.get("1.0", tk.END).strip():
            messagebox.showinfo("Nothing to Save", "No results to save. Crack a message first.")
            return

        # Generate default filename
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"enigma_result_{ts}.txt"

        filepath = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=default_name
        )
        if not filepath:
            return

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("═══════════════════════════════════════════════════════\n")
                f.write("  ENIGMA CRACKER — RESULTS\n")
                f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("═══════════════════════════════════════════════════════\n\n")

                if self.last_result:
                    r = self.last_result
                    f.write(f"Mode:        {r.get('mode', '?')}\n")
                    f.write(f"Rotors:      {r.get('rotors', '?')}\n")
                    f.write(f"Reflector:   {r.get('reflector', '?')}\n")
                    f.write(f"Positions:   {r.get('positions', '?')}\n")
                    f.write(f"Rings:       {r.get('rings', '?')}\n")
                    if r.get('mode') == 'M4':
                        f.write(f"Thin rotor:  {r.get('thin_rotor', '?')}\n")
                        f.write(f"Thin pos:    {r.get('thin_position', '?')}\n")
                        f.write(f"Thin ring:   {r.get('thin_ring', '?')}\n")
                    f.write(f"Plugboard:   {r.get('plugboard', '(none)')}\n")
                    f.write(f"German score:{r.get('german_score', 0)}\n")
                    f.write(f"Configs:     {r.get('configs_tried', 0):,}\n")
                    f.write(f"Elapsed:     {r.get('elapsed_time', 0):.2f}s\n")
                    f.write(f"\n")
                    f.write(f"Plaintext:\n")
                    f.write(f"  {r.get('plaintext', '')}\n")
                else:
                    # Fall back to raw output
                    raw = self.raw_text.get("1.0", tk.END)
                    f.write(raw)

                f.write("\n")
                f.write("═══════════════════════════════════════════════════════\n")

            messagebox.showinfo("Saved", f"Results saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save:\n{e}")

    def on_recompile(self):
        self.status_label.config(text="Compiling...")
        self.root.update()
        ok, msg = compile_binary()
        self.status_label.config(text=msg)
        if ok:
            messagebox.showinfo("Compiled", msg)
        else:
            messagebox.showerror("Compilation Failed", msg)

    def on_about(self):
        messagebox.showinfo("About Enigma Cracker",
            "Enigma Cracker GUI\n\n"
            "Brute-force cracker for Enigma M3 (3-rotor) and M4 (4-rotor Naval) machines.\n\n"
            "Backend: enigma_cracker.c (C)\n"
            "GUI: Python Tkinter\n\n"
            "Methodology:\n"
            "  1. Rotor permutation search (Index of Coincidence)\n"
            "  2. Ring settings search\n"
            "  3. Plugboard hill climbing (German trigram fitness)\n\n"
            "Cross-platform: Linux (gcc) and Windows (MinGW)")

    def on_usage(self):
        messagebox.showinfo("Usage Guide",
            "How to use:\n\n"
            "1. Paste Enigma ciphertext into the input box (A-Z, spaces ignored)\n"
            "2. Select M3 or M4 mode\n"
            "3. Click 'Crack' — this may take several seconds to minutes\n"
            "4. Results appear below: settings, plaintext, elapsed time\n"
            "5. Click 'Save Results' to export to a text file\n\n"
            "Tips:\n"
            "- M3 is faster (60 rotor permutations vs M4's much larger search space)\n"
            "- M4 cracking can take significantly longer due to the thin rotor\n"
            "- Longer ciphertexts produce more reliable results\n"
            "- The cracker searches rotors I-V for M3, adds beta/gamma for M4\n"
            "- If no solution is found, try the other mode\n\n"
            "Windows setup:\n"
            "  Install MinGW-w64 (via MSYS2 recommended):\n"
            "  pacman -S mingw-w64-x86_64-gcc\n"
            "  Then run: python enigma_gui.py")


# ─── Entry point ───

def main():
    root = tk.Tk()
    app = EnigmaCrackerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()