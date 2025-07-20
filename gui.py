import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from rule_parser import parse_rules
from compliance_checker import check_compliance

class FirewallToolGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Firewall Configuration Self-Assessment Tool")
        self.geometry("700x500")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Firewall Rule Assessment Tool", font=("Arial", 16)).pack(pady=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Import Rules (Simulated)", command=self.import_rules).grid(row=0, column=0, padx=10)
        tk.Button(btn_frame, text="Run Compliance Check", command=self.run_compliance).grid(row=0, column=1, padx=10)

        self.output = scrolledtext.ScrolledText(self, width=80, height=20)
        self.output.pack(padx=20, pady=20)

    def import_rules(self):
        # Simulate importing firewall rules
        self.rules = [
            {"id": 1, "port": 80, "action": "allow"},
            {"id": 2, "port": 23, "action": "allow"},
            {"id": 3, "port": 443, "action": "deny"}
        ]
        self.output.insert(tk.END, "Imported rules:\n" + str(self.rules) + "\n\n")

    def run_compliance(self):
        if not hasattr(self, 'rules'):
            messagebox.showwarning("Error", "No rules imported yet!")
            return
        normalized = parse_rules(self.rules)
        compliance_report = check_compliance(normalized)
        self.output.insert(tk.END, "Compliance Results:\n" + compliance_report + "\n\n")
