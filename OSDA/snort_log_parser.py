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


def main():
    with open("/var/log/snort/alert_fast.txt", "rt") as fd:
        logs = fd.readlines()

    # Index Number
    # 0 : Date Time
    # 1 : Rule Name
    # 2 : Classification
    # 3 : Priority
    # 4 : Network Protocol
    # 5 : Source IP
    # 6 : Source Port
    # 7 : Destination IP
    # 8 : Destination Port

    print(bcolors.HEADER + "[*] Snort Audit Log" + bcolors.END)
    pattern = re.compile(r'(.*?)\..*?"(.*?)".*?(?:\[Classification: (.*?)\])* \[Priority: (.*?)\].*?{(.*?)} (.*?):(\d+) -> (.*?):(\d+)')
    for snort_log in [pattern.match(log).groups() for log in logs if pattern.search(log)]:
        if snort_log[3] == "1" or snort_log[3] == "2":
            message = bcolors.ERR
        else:
            message = bcolors.WARN
        message += "{}" + bcolors.END

        print(message.format('[{0}] ({2}) "{1}" {5}:{6} -> {7}:{8} ({4})'.format(snort_log[0].replace("-", " "), *snort_log[1:])))


if __name__ == "__main__":
    main()
