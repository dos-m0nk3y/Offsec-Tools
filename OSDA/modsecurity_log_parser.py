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
    with open("/etc/os-release", "rt") as fd:
        os_name = fd.readline()

    if "CentOS" in os_name:
        log_file = "/var/log/httpd/modsec_audit.log"
    elif "Ubuntu" in os_name:
        log_file = "/var/log/apache2/modsec_audit.log"

    with open(log_file, "rt") as fd:
        transactions = re.split(r"--\w+-Z--", fd.read())

    whitelists = ["Host header is a numeric IP address", "Inbound Anomaly Score Exceeded"]
    for transaction in transactions:
        for header in re.findall(r"--\w+-\w--", transaction):
            section = transaction.split(header)[1]
            section = re.split(r"--\w+-\w--", section)[0].strip()

            if header[-3] == "A":
                log_header = section
            elif header[-3] == "B":
                request_headers = section
            elif header[-3] == "C":
                request_body = section
            elif header[-3] == "H":
                warnings = [warning for warning in section.split("\n") if "Message: Warning." in warning]
                warnings = [warning for warning in warnings if True not in [whitelist in warning for whitelist in whitelists]]
                warnings = [re.findall(r'\[msg "(.*?)"\]', warning)[0] for warning in warnings if re.search(r'\[msg "(.*?)"\]', warning)]

        if len(warnings) != 0:
            timestamp, src_ip, src_port, dst_ip, dst_port = re.match(r"\[(.*?) --\d{4}\] .*? ([(\d\.)]+) (\d+) ([(\d\.)]+) (\d+)", log_header).groups()
            print(bcolors.ERRMSG + ", ".join(warnings) + bcolors.END)
            print("{}[{}] {}:{} -> {}:{}{}".format(bcolors.WARN, timestamp, src_ip, src_port, dst_ip, dst_port, bcolors.END))
            print(request_headers)
            try:
                print("\n" + request_body)
            except Exception:
                pass
            print("")


if __name__ == "__main__":
    main()
