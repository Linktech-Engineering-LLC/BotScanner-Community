#!/usr/bin/env python3
"""
 File: svnci.py
 Author: Leon McClatchey
 Date: 2025-11-24

"""
# --- System Library Imports ---
import subprocess
import sys

def run(cmd):
    """Run a shell command and return (exit_code, output)."""
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        return result.returncode, result.stdout + result.stderr
    except Exception as e:
        return 1, str(e)

def main():
    if len(sys.argv) < 2:
        print("Usage: svnci.py -m \"commit message\" [other svn commit args]")
        sys.exit(1)

    # Step 1: Update before commit
    print("Running svn update...")
    code, output = run(["svn", "update"])
    print(output)
    if code != 0:
        print("svn update failed. Aborting commit.")
        sys.exit(code)

    # Step 2: Commit with provided arguments
    print("Running svn commit...")
    code, output = run(["svn", "commit"] + sys.argv[1:])
    print(output)
    sys.exit(code)

if __name__ == "__main__":
    main()
