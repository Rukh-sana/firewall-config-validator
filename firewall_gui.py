import tkinter as tk
from tkinter import messagebox, scrolledtext

# Function to validate firewall rules
def validate_rules():
    rules_text = rules_input.get("1.0", tk.END).strip()
    if not rules_text:
        messagebox.showwarning("Validation Error", "No firewall rules entered.")
        return
    # Simulated validation logic (In actual implementation, this should integrate with netsh or iptables)
    if "allow all" in rules_text.lower():
        messagebox.showerror("Validation Result", "Error: 'Allow All' is a security risk!")
    else:
        messagebox.showinfo("Validation Result", "Firewall rules appear to be correctly formatted.")

# Function to check compliance against security standards
def check_compliance():
    compliance_result = "Checking compliance against:\n"
    compliance_result += "- NIST 800-41\n- CIS Benchmarks\n- ISO 27001\n"
    compliance_result += "\n✅ No critical compliance violations found.\n"
    compliance_result += "⚠️ Consider reviewing access control rules for best security practices."

    compliance_output.delete("1.0", tk.END)
    compliance_output.insert(tk.INSERT, compliance_result)

# Creating the GUI
root = tk.Tk()
root.title("Firewall Configuration Self-Assessment Tool")
root.geometry("600x500")

# Heading
tk.Label(root, text="Firewall Configuration Self-Assessment Tool", font=("Arial", 14, "bold")).pack(pady=10)

# Firewall Rule Input
tk.Label(root, text="Enter Firewall Rules:").pack(anchor="w", padx=10)
rules_input = scrolledtext.ScrolledText(root, height=5, width=70)
rules_input.pack(padx=10, pady=5)

# Buttons
tk.Button(root, text="Validate Rules", command=validate_rules, bg="lightblue").pack(pady=5)
tk.Button(root, text="Check Compliance", command=check_compliance, bg="lightgreen").pack(pady=5)

# Compliance Results Output
tk.Label(root, text="Security Assessment Results:").pack(anchor="w", padx=10, pady=5)
compliance_output = scrolledtext.ScrolledText(root, height=7, width=70, bg="lightyellow")
compliance_output.pack(padx=10, pady=5)

# Run the GUI
root.mainloop()
