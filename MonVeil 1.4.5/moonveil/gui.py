"""Tkinter front end for the MoonVeil v1.4.5 decompiler."""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

from . import __version__


def main() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("Tkinter is not available in this Python installation.", file=sys.stderr)
        return 2

    root = tk.Tk()
    root.title(f"MoonVeil v1.4.5 Deobfuscator {__version__}")
    root.geometry("740x450")
    root.minsize(640, 400)

    input_value = tk.StringVar()
    output_value = tk.StringVar()
    artifacts_value = tk.StringVar()
    verify_value = tk.BooleanVar(value=True)
    status_value = tk.StringVar(value="Choose a complete MoonVeil v1.4.5 .lua file.")

    frame = ttk.Frame(root, padding=14)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(1, weight=1)
    frame.rowconfigure(5, weight=1)

    def choose_input() -> None:
        selected = filedialog.askopenfilename(
            title="Choose MoonVeil-obfuscated Luau",
            filetypes=[("Lua and Luau", "*.lua *.luau"), ("All files", "*.*")],
        )
        if not selected:
            return
        source = Path(selected)
        input_value.set(str(source))
        output_value.set(str(source.with_name(source.stem + ".deobfuscated.luau")))
        artifacts_value.set(str(source.with_name(source.stem + ".moonveil")))

    def choose_output() -> None:
        selected = filedialog.asksaveasfilename(
            title="Save recovered Luau",
            defaultextension=".luau",
            filetypes=[("Luau", "*.luau"), ("Lua", "*.lua"), ("All files", "*.*")],
        )
        if selected:
            output_value.set(selected)

    ttk.Label(frame, text="Obfuscated input").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=5)
    ttk.Entry(frame, textvariable=input_value).grid(row=0, column=1, sticky="ew", pady=5)
    ttk.Button(frame, text="Browse…", command=choose_input).grid(row=0, column=2, padx=(8, 0), pady=5)

    ttk.Label(frame, text="Recovered output").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=5)
    ttk.Entry(frame, textvariable=output_value).grid(row=1, column=1, sticky="ew", pady=5)
    ttk.Button(frame, text="Save as…", command=choose_output).grid(row=1, column=2, padx=(8, 0), pady=5)

    ttk.Label(frame, text="Artifacts folder").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=5)
    ttk.Entry(frame, textvariable=artifacts_value).grid(row=2, column=1, sticky="ew", pady=5)
    ttk.Checkbutton(frame, text="Verify behavior when supported", variable=verify_value).grid(row=3, column=1, sticky="w", pady=(5, 9))

    controls = ttk.Frame(frame)
    controls.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 8))
    controls.columnconfigure(1, weight=1)
    run_button = ttk.Button(controls, text="Decompile")
    run_button.grid(row=0, column=0, sticky="w")
    ttk.Label(controls, textvariable=status_value).grid(row=0, column=1, sticky="w", padx=12)

    log = tk.Text(frame, height=15, wrap="word", state="disabled")
    log.grid(row=5, column=0, columnspan=3, sticky="nsew")
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=log.yview)
    scrollbar.grid(row=5, column=3, sticky="ns")
    log.configure(yscrollcommand=scrollbar.set)

    def set_log(text: str) -> None:
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", text)
        log.configure(state="disabled")

    def finished(returncode: int, text: str, output: Path) -> None:
        run_button.configure(state="normal")
        set_log(text)
        if returncode == 0:
            status_value.set(f"Finished: {output.name}")
            messagebox.showinfo("MoonVeil Deobfuscator", f"Recovered Luau written to:\n{output}")
        else:
            status_value.set("Decompilation failed; see the log below.")
            messagebox.showerror("MoonVeil Deobfuscator", "Decompilation failed. See the log for details.")

    def run_decompile() -> None:
        source = Path(input_value.get()).expanduser()
        output = Path(output_value.get()).expanduser()
        if not source.is_file():
            messagebox.showerror("MoonVeil Deobfuscator", "Choose an existing input file.")
            return
        if not output_value.get().strip():
            messagebox.showerror("MoonVeil Deobfuscator", "Choose an output file.")
            return
        command = [sys.executable, "-m", "moonveil", "decompile", str(source), "-o", str(output)]
        artifacts = artifacts_value.get().strip()
        if artifacts:
            command.extend(["--artifacts", artifacts])
        if not verify_value.get():
            command.append("--no-verify")
        run_button.configure(state="disabled")
        status_value.set("Recovering and reconstructing v1.4.5 (verification is capped at 10s)…")
        set_log("Running:\n" + subprocess.list2cmdline(command) + "\n\n")

        def worker() -> None:
            completed = subprocess.run(
                command,
                cwd=Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                check=False,
            )
            root.after(0, finished, completed.returncode, completed.stdout, output.resolve())

        threading.Thread(target=worker, daemon=True).start()

    run_button.configure(command=run_decompile)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())