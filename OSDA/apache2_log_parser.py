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


def format_log(log):
    template = '{} [{}] "{} {} {}" {} {} "{}" "{}"'
    if log[9] is not None:
        template += ' "{}"'
    return template.format(*log)


def main():
    with open("/etc/os-release", "rt") as fd:
        os_name = fd.readline()

    if "CentOS" in os_name:
        log_file = "/var/log/httpd/access_log"
    elif "Ubuntu" in os_name:
        log_file = "/var/log/apache2/access.log"

    with open(log_file, "rt") as fd:
        logs = fd.readlines()

    # Index Number
    # 0 : Source IP
    # 1 : Date Time
    # 2 : Resource Method
    # 3 : Resource Path
    # 4 : Request Version
    # 5 : Response Status
    # 6 : Resource Size
    # 7 : Referer
    # 8 : User-Agent
    # 9 : Cookies

    pattern = re.compile(r"([(\d\.)]+) - - \[(.*?) -\d{4}\] \"(.*?) (.*?) (.*?)\" (\d+) (\d+) \"(.*?)\" \"(.*?)\"(?: \"(.*?)\")*")
    apache_logs = [pattern.match(log).groups() for log in logs if pattern.search(log)]
    # print(bcolors.HEADER + "[*] Entire Log" + bcolors.END)
    # print("\n".join([format_log(apache_log) for apache_log in apache_logs]))

    print(bcolors.HEADER + "[*] Shellshock Attempts" + bcolors.END)
    pattern = re.compile(r"\(\)\s*\t*\{.*;\s*\}\s*;")
    for shellshock_log in apache_logs:
        if not pattern.search(format_log(shellshock_log)):
            continue
        if shellshock_log[5] == "200":
            message = bcolors.ERRMSG
        else:
            message = bcolors.WAITMSG
        message += "{}" + bcolors.END
        print(message.format(format_log(shellshock_log)))


if __name__ == "__main__":
    main()
