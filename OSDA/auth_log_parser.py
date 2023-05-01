import re


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


def parse_sshd_log(logs):
    # Set `LogLevel` to `DEBUG1` in `sshd_config` to log public key failure
    # Index Number
    # 0 : Date Time
    # 1 : Authentication Status (Accepted / Failed)
    # 2 : Authentication Type (password / publickey)
    # 4 : Username ($USER / invalid user $USER)
    # 5 : IP Address
    # 6 : Port

    print(bcolors.HEADER + "[*] SSH Audit Log" + bcolors.END)
    pattern = re.compile(r"(?:<\d+>)*(\w{3} \d{2} \d{2}:\d{2}:\d{2}).*?sshd\[\d+\]:\s*(\w+) (\w+) for (.*?) from (\d+.\d+.\d+.\d+) port (\d+)")

    for login_log in [pattern.match(login_log).groups() for login_log in logs if pattern.search(login_log)]:
        if "Accepted" in login_log[1]:
            message = bcolors.OKMSG
        elif "Failed" in login_log[1]:
            message = bcolors.ERRMSG
        else:
            message = bcolors.WAITMSG
        message += "{}" + bcolors.END
        print(message.format(" ".join(login_log)))


def parse_sudo_log(logs):
    print("\n" + bcolors.HEADER + "[*] Sudo Audit Log" + bcolors.END)
    pattern = re.compile(r"(?:<\d+>)*(\w{3} \d{2} \d{2}:\d{2}:\d{2})\s*\w+\s*sudo:\s*(.*?)\s*:\s*((?:.*;){3}.*)")

    for sudo_log in [sudo_log.strip() for sudo_log in logs if pattern.search(sudo_log)]:
        timestamp, from_user, info = pattern.match(sudo_log).groups()
        info = [detail.strip() for detail in info.split(";")]
        msg = info[0] if (len(info) == 5) else None
        to_user = info[-2][5:]
        command = info[-1][8:]

        sudo_log = "[{}] ({} -> {}) {}".format(timestamp, from_user, to_user, command)
        if msg is not None:
            sudo_log += f" ({msg})"

        if msg is None:
            message = bcolors.OKMSG
        else:
            message = bcolors.ERRMSG
        message += "{}" + bcolors.END
        print(message.format(sudo_log))


def main():
    with open("/etc/os-release", "rt") as fd:
        os_name = fd.readline()

    if "CentOS" in os_name:
        log_file = "/var/log/secure"
    elif "Ubuntu" in os_name or "Kali" in os_name:
        log_file = "/var/log/auth.log"

    with open(log_file, "rt") as fd:
        logs = fd.readlines()

    parse_sshd_log(logs)
    parse_sudo_log(logs)


if __name__ == "__main__":
    main()
