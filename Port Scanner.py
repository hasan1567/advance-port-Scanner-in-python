import socket, csv, json, os, tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor
import threading
import nmap

def tcp_scan(host, port, timeout, results, banners_only, progress_bar, result_area):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        banner = ""
        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            pass
        entry = {"port": port, "proto": "TCP", "service": banner or "Unknown", "banner": banner}
        if not banners_only or banner:
            results.append(entry)
            result_area.insert(tk.END, f"✅ TCP {port} open — {banner or '[no banner]'}\n")
    except:
        pass
    finally:
        s.close()
        progress_bar.step()

def udp_scan(host, port, timeout, results, banners_only, progress_bar, result_area):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b'', (host, port))
        s.recvfrom(1024)
        entry = {"port": port, "proto": "UDP", "service": "open/filtered", "banner": ""}
        if not banners_only:
            results.append(entry)
            result_area.insert(tk.END, f"✅ UDP {port} open/filtered\n")
    except:
        pass
    finally:
        s.close()
        progress_bar.step()

def nmap_scan(host, start, end, results, banners_only, progress_bar, result_area):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=host, ports=f"{start}-{end}", arguments='-sV')
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                info = nm[host][proto][port]
                svc = info.get('name', '')
                ver = info.get('version', '')
                line = f"{svc} {ver}".strip()
                if not banners_only or svc or ver:
                    results.append({"port": port, "proto": proto.upper(), "service": line, "banner": ""})
                    result_area.insert(tk.END, f"🕵️ Nmap {proto.upper()} {port} — {line}\n")
                progress_bar.step()
    except Exception as e:
        result_area.insert(tk.END, f"⚠️ Nmap error: {e}\n")

def run_scan(host, start, end, scan_type, mode, banners_only, result_area, progress_bar, results):
    result_area.delete("1.0", tk.END)
    results.clear()
    total = (end - start + 1) * ({"TCP":1, "UDP":1, "Nmap":1, "All":3}[scan_type])
    progress_bar["maximum"] = total
    timeout = 0.3 if mode == "Aggressive" else 1.5

    with ThreadPoolExecutor(max_workers=50 if mode=="Aggressive" else 10) as exe:
        futures = []
        for p in range(start, end+1):
            if scan_type in ("TCP", "All"):
                futures.append(exe.submit(tcp_scan, host, p, timeout, results, banners_only, progress_bar, result_area))
            if scan_type in ("UDP", "All"):
                futures.append(exe.submit(udp_scan, host, p, timeout, results, banners_only, progress_bar, result_area))
        for f in futures: f.result()
        if scan_type in ("Nmap", "All"):
            nmap_scan(host, start, end, results, banners_only, progress_bar, result_area)

    result_area.insert(tk.END, "\n✅ Scan finished.\n")

def start_scan(hostE, sE, eE, scan_var, mode_var, banner_var, result_area, progress, results):
    try:
        host = hostE.get().strip()
        s = int(sE.get())
        e = int(eE.get())
        if s < 0 or e > 65535 or s > e:
            raise ValueError
        threading.Thread(target=run_scan, args=(host, s, e, scan_var.get(), mode_var.get(), banner_var.get(), result_area, progress, results), daemon=True).start()
    except ValueError:
        messagebox.showerror("Input Error", "Enter a valid host and port range (0–65535)")

def export_results(results):
    if not results:
        messagebox.showinfo("Nothing to export", "No results to save.")
        return
    path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("CSV","*.csv"),("JSON","*.json")])
    if not path: return
    if path.endswith(".csv"):
        with open(path, "w", newline='') as f:
            csv.DictWriter(f, fieldnames=["port","proto","service","banner"]).writerows(results)
    else:
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
    messagebox.showinfo("Saved", f"Results saved to {path}")

def apply_dark(widget):
    bg, fg = "#2e2e2e", "#e0e0e0"
    try:
        cls = widget.winfo_class()
        if cls=="Frame": widget.configure(bg=bg)
        elif cls in ("Label", "Button", "Checkbutton", "Radiobutton"): widget.configure(bg=bg, fg=fg)
        elif cls=="Entry": widget.configure(bg="#3a3a3a", fg=fg, insertbackground="white")
        elif cls=="Text": widget.configure(bg="#3a3a3a", fg=fg, insertbackground="white")
    except: pass
    for c in widget.winfo_children(): apply_dark(c)

def apply_port_preset(preset, sE, eE):
    if preset == "Top 100 Common Ports":
        sE.delete(0, tk.END); eE.delete(0, tk.END)
        sE.insert(0, "1"); eE.insert(0, "1024")
    elif preset == "Web Ports (80,443,8080)":
        sE.delete(0, tk.END); eE.delete(0, tk.END)
        sE.insert(0, "80"); eE.insert(0, "8080")
    elif preset == "Custom":
        sE.delete(0, tk.END); eE.delete(0, tk.END)

# GUI Setup
app = tk.Tk()
app.title("📡 Pro Port Scanner")

# ✅ Link the custom .ico icon (must exist in same folder or full path)
icon_path = os.path.abspath("scanner_icon.ico")
if os.path.exists(icon_path):
    app.iconbitmap(default=icon_path)

frm = tk.Frame(app); frm.pack(padx=10, pady=10)
tk.Label(frm, text="Host:").grid(row=0, column=0, sticky="e")
hostE = tk.Entry(frm, width=30); hostE.grid(row=0, column=1, pady=2)

tk.Label(frm, text="Ports:").grid(row=1, column=0, sticky="e")
sE = tk.Entry(frm, width=6); sE.grid(row=1, column=1, sticky="w", pady=2)
eE = tk.Entry(frm, width=6); eE.grid(row=1, column=1, padx=70, pady=2)

tk.Label(frm, text="Presets:").grid(row=2, column=0, sticky="e")
preset_var = tk.StringVar(value="Custom")
preset_box = ttk.Combobox(frm, textvariable=preset_var, values=["Top 100 Common Ports", "Web Ports (80,443,8080)", "Custom"], state="readonly")
preset_box.grid(row=2, column=1, sticky="w")
preset_box.bind("<<ComboboxSelected>>", lambda e: apply_port_preset(preset_var.get(), sE, eE))

tk.Label(frm, text="Scan Type:").grid(row=3, column=0, sticky="e")
scan_var = tk.StringVar(value="All")
ttk.Combobox(frm, textvariable=scan_var, values=["TCP","UDP","Nmap","All"], state="readonly").grid(row=3, column=1, sticky="w")

tk.Label(frm, text="Mode:").grid(row=4, column=0, sticky="e")
mode_var = tk.StringVar(value="Aggressive")
tk.Radiobutton(frm, text="Aggressive", variable=mode_var, value="Aggressive").grid(row=4, column=1, sticky="w")
tk.Radiobutton(frm, text="Stealth", variable=mode_var, value="Stealth").grid(row=4, column=1, padx=100, sticky="w")

banner_var = tk.BooleanVar()
tk.Checkbutton(frm, text="Only show ports with banners/services", variable=banner_var).grid(row=5, column=0, columnspan=2, sticky="w")

tk.Button(frm, text="Start Scan", command=lambda: start_scan(hostE, sE, eE, scan_var, mode_var, banner_var, result_area, progress, results)).grid(row=6, column=1, sticky="w", pady=5)
tk.Button(frm, text="Export Results", command=lambda: export_results(results)).grid(row=6, column=0, sticky="e", pady=5)

progress = ttk.Progressbar(frm, orient="horizontal", length=300, mode="determinate")
progress.grid(row=7, column=0, columnspan=2, pady=5)

result_area = scrolledtext.ScrolledText(app, width=80, height=20)
result_area.pack(padx=10, pady=10)

results = []

style = ttk.Style()
style.theme_use("clam")
style.configure("Horizontal.TProgressbar", background="#00ff00", troughcolor="#2e2e2e")

apply_dark(app)
app.mainloop()
