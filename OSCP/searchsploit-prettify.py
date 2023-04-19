#!/usr/bin/python3

import sys
import json
import subprocess
import prettytable


if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <terms>")
    sys.exit(0)

argv = " ".join(sys.argv[1:])
result = subprocess.check_output(f"searchsploit '{argv}' -j", shell=True).decode()

table = prettytable.PrettyTable(junction_char=" ")
table.field_names = ["Exploit Title", "Path"]
table.align = "l"

for row in [[row["Title"], row["Path"]] for row in json.loads(result)["RESULTS_EXPLOIT"]]:
    table.add_row(row)

print(table)

