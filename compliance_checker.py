def check_compliance(normalized_rules):
    issues = []
    for rule in normalized_rules:
        if rule["port"] == 23 and rule["action"] == "allow":
            issues.append(f"❌ Rule {rule['id']} allows insecure port 23 (Telnet)")
        elif rule["action"] == "deny":
            issues.append(f"ℹ️ Rule {rule['id']} blocks traffic — ensure necessity")
        else:
            issues.append(f"✔️ Rule {rule['id']} is compliant")

    return "\n".join(issues)
