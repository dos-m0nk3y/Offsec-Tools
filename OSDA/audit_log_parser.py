import re
from datetime import datetime


class bcolors:
    OK = "\033[92m"
    WARN = "\033[93m"
    ERR = "\033[31m"
    UNDERLINE = "\033[4m"
    ITALIC = "\x1B[3m"
    BOLD = "\033[1m"
    BLUE = "\033[94m"
    ENDC = "\033[0m"

    HEADER = "\033[95m" + BOLD
    PASS = OK + BOLD
    FAIL = ERR + BOLD

    OKMSG = BOLD + OK + "\u2705" + "  "
    ERRMSG = BOLD + FAIL + "\u274C" + "  "
    WAITMSG = BOLD + WARN + "\u231b" + "  "

    HELP = WARN
    BITALIC = BOLD + ITALIC
    BLUEIC = BITALIC + OK
    END = ENDC


def main():
    with open("/etc/passwd", "rt") as fd:
        entries = fd.readlines()

    users = {}
    for entry in entries:
        users[entry.split(":")[2]] = entry.split(":")[0]

    with open("/var/log/audit/audit.log", "rt") as fd:
        logs = fd.readlines()

    print(bcolors.HEADER + "[*] TTY Audit Log" + bcolors.END)
    pattern = re.compile(r'type=TTY msg=audit\((\d+).\d+(?::\d+)\): tty pid=(\d+) uid=(\d+) auid=(\d+) ses=\d+ major=\d+ minor=\d+ comm="(.*?)" data=(.*)')

    # https://en.wikipedia.org/wiki/ANSI_escape_code
    escape_codes = {
        b"\x1B[1~": b"<Home>",
        b"\x1B[2~": b"<Insert>",
        b"\x1B[3~": b"<Delete>",
        b"\x1B[4~": b"<End>",
        b"\x1B[5~": b"<PgUp>",
        b"\x1B[6~": b"<PgDn>",
        b"\x1B[7~": b"<Home>",
        b"\x1B[8~": b"<End>",
        b"\x1B[A": b"<Up>",
        b"\x1B[B": b"<Down>",
        b"\x1B[C": b"<Right>",
        b"\x1B[D": b"<Left>",
        b"\x1B[F": b"<End>",
        b"\x1B[H": b"<Home>",
        b"\x1B[200~": b"",
        b"\x1B[201~": b"",
        b"\x1BOA": b"",
        b"\x1BOH": b"",
    }

    ascii_chars = {}
    for i in range(0x20):
        ascii_chars[chr(i).encode()] = b""
    ascii_chars[b"\x09"] = b"<Tab>"
    ascii_chars[b"\x0D"] = b"\n"
    ascii_chars[b"\x1B"] = b"<Esc>"
    ascii_chars[b"\x7F"] = b"<Backspace>"

    for tty_log in [pattern.match(tty_log).groups() for tty_log in logs if pattern.search(tty_log)]:
        timestamp = datetime.fromtimestamp(int(tty_log[0]))
        pid = tty_log[1]
        username = users[tty_log[2]]
        a_username = users[tty_log[3]]
        process = tty_log[4]
        command = bytes(bytearray.fromhex(tty_log[5]))
        for escape_code in escape_codes.items():
            command = command.replace(escape_code[0], escape_code[1])
        for ascii_char in ascii_chars.items():
            command = command.replace(ascii_char[0], ascii_char[1])

        print("{}[{}] ({}:{}) -> {}({}){}".format(bcolors.PASS, timestamp, username, a_username, process, pid, bcolors.END))
        print(command.decode())


if __name__ == "__main__":
    main()
