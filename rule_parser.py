def parse_rules(rules):
    # Simulate normalization
    for rule in rules:
        rule["normalized"] = f"port_{rule['port']}_{rule['action']}"
    return rules
