#!/usr/bin/env python3
import yaml

with open("templates/script_manifest.yml") as f:
    manifest = yaml.safe_load(f)

def print_unchecked(manifest):
    for script in manifest.get("scripts", []):
        name = script.get("name")
        checklist = script.get("checklist", {})
        for item, done in checklist.items():
            if not done:
                print(f"[ ] {name}: {item}")
    for item, done in manifest.get("integration_tasks", {}).items():
        if not done:
            print(f"[ ] integration: {item}")

print_unchecked(manifest)