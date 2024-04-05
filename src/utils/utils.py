import distro
from ctypes import windll
from configparser import ConfigParser
from datetime import datetime
from os import get_terminal_size, getuid
from platform import platform, system
from re import search
from socket import AF_INET, SOCK_DGRAM, socket
from subprocess import DEVNULL, PIPE, CalledProcessError, Popen, check_call
from sys import platform as sys_platform

from requests import get
from rich.text import Text

from src.data.dataclass import ScanMode, ScanType
from src.utils.report import ReportMail, ReportType


def is_root() -> bool: #! fix this shit
    try:
        if platform() != "windows":
            return getuid() == 0

        return windll.shell32.IsUserAnAdmin() == 1
    except (OSError, PermissionError) as err:
        raise SystemExit(
            f"Cannot determine permissions: {err}"
        ) from err

def GetIpAdress() -> str: #! fix this shit
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    PrivateIPAdress = s.getsockname()[0]
    return PrivateIPAdress


def DetectIPRange() -> str:
    net_dict: dict[str, int] = {
        "255.255.255.255": 32,
        "255.255.255.254": 31,
        "255.255.255.252": 30,
        "255.255.255.248": 29,
        "255.255.255.240": 28,
        "255.255.255.224": 27,
        "255.255.255.192": 26,
        "255.255.255.128": 25,
        "255.255.255.0": 24,
        "255.255.254.0": 23,
        "255.255.252.0": 22,
        "255.255.248.0": 21,
        "255.255.240.0": 20,
        "255.255.224.0": 19,
        "255.255.192.0": 18,
        "255.255.128.0": 17,
        "255.255.0.0": 16,
    }
    ip = GetIpAdress()
    if system().lower() == "windows":
        proc = Popen("ipconfig", stdout=PIPE)
        while True:
            line = proc.stdout.readline()
            if ip.encode() in line:
                break
        mask = (
                proc
                    .stdout
                    .readline()
                    .rstrip()
                    .split(b":")[-1]
                    .replace(b" ", b"")
                    .decode()
            )
        net_range = f"{ip}/{net_dict[mask]}"
    else:
        proc = Popen(
                [
                    "ip",
                    "-o",
                    "-f",
                    "inet",
                    "addr",
                    "show"
                ],
                stdout=PIPE
            )
        regex = f"\\b{ip}\/\\b([0-9]|[12][0-9]|3[0-2])\\b"
        cmd_output = proc.stdout.read().decode()
        net_range = search(regex, cmd_output).group()

    return net_range


def InitAutomation(args) -> None: #! fix this shit
    global DontAskForConfirmation
    if args.yes_please:
        DontAskForConfirmation = True
    else:
        DontAskForConfirmation = False


def InitArgsAPI(args, log) -> str:
    if args.api:
        apiKey = args.api

    else:
        apiKey = None
        try:
            with open("api.txt", "r", encoding="utf-8") as f:
                apiKey = f.readline().strip("\n")
        except FileNotFoundError:
            log.logger(
                "warning",
                (
                    "No API key specified and no api.txt file found. "
                    "Vulnerability detection is going to be slower! "
                    "You can get your own NIST API key from "
                    "https://nvd.nist.gov/developers/request-an-api-key"
                )
            )
        except PermissionError:
            log.logger(
                "error",
                "Permission denied while trying to read api.txt!"
            )

    return apiKey


def InitArgsScanType(args, log) -> ScanType: #! fix this shit
    scantype = ScanType.PING
    if args.scan_type == "arp":
        if is_root():
            scantype = ScanType.ARP
        else:
            log.logger(
                "warning",
                (
                    "You need to be root in order to run arp"
                    "scan.\nChanged scan mode to Ping Scan."
                ),
            )
    elif args.scan_type is None or args.scan_type == "":
        if is_root():
            scantype = ScanType.ARP

    return scantype


def InitArgsTarget(args, log): #! fix this shit
    if args.target:
        target = args.target
    else:
        if args.host_file:
            # read targets from host file and insert all of them into an array
            try:
                with open(
                        args.host_file,
                        "r",
                        encoding="utf-8"
                    ) as target_file:
                    target = target_file.read().splitlines()
            except FileNotFoundError:
                log.logger("error", "Host file not found!")
            except PermissionError:
                log.logger(
                    "error",
                    (
                        "Permission denied while"
                        "trying to read host file!"
                    )
                )
            except Exception:
                log.logger(
                    "error",
                    (
                        "Unknown error while"
                        "trying to read host file!"
                    )
                )
            else:
                return target

            target = DetectIPRange()
        else:
            if DontAskForConfirmation:
                try:
                    target = DetectIPRange()
                except Exception as e: #! fix this crap
                    log.logger("error", e)
                    target = input("Enter target range to scan: ")
            else:
                try:
                    target = input("Enter target range to scan: ")
                except KeyboardInterrupt as err:
                    raise SystemExit("Ctrl+C pressed. Exiting.") from err

    return target


def InitArgsMode(args, log) -> ScanMode:
    scanmode = ScanMode.NORMAL

    if args.mode == "evade":
        if is_root():
            scanmode = ScanMode.EVADE
            log.logger("info", "Evasion mode enabled!")
        else:
            log.logger(
                "error",
                "You must be root to use evasion mode!"
                + " Switching back to normal mode ...",
            )
    elif args.mode == "noise":
        scanmode = ScanMode.NOISE
        log.logger("info", "Noise mode enabled!")

    return scanmode


def InitReport(args, log) -> tuple:
    if not args.report:
        return ReportType.NONE, None

    if args.report == "email":
        Method = ReportType.EMAIL
        if args.report_email:
            ReportEmail = args.report_email
        else:
            ReportEmail = input("Enter your email address: ")

        if args.report_email_password:
            ReportMailPassword = args.report_email_password
        else:
            ReportMailPassword = input("Enter your email password: ")

        if args.report_email_to:
            ReportMailTo = args.report_email_to
        else:
            ReportMailTo = input(
                    "Enter the email address to send the report to: "
                )

        if args.report_email_from:
            ReportMailFrom = args.report_email_from
        else:
            ReportMailFrom = ReportEmail

        if args.report_email_server:
            ReportMailServer = args.report_email_server
        else:
            ReportMailServer = input(
                "Enter the email server to send the report from: "
            )
            if ReportMailServer == "smtp.gmail.com":
                log.logger(
                    "warning",
                    "Google no longer supports sending mails via SMTP."
                )
                return ReportType.NONE, None

        if args.report_email_server_port:
            ReportMailPort = args.report_email_server_port
        else:
            while True:
                ReportMailPort = input(
                    "Enter the email port to send the report from: "
                )
                if not isinstance(ReportMailPort, int):
                    break
                log.logger("error", "Invalid port number!")

        EmailObj = ReportMail(
            ReportEmail,
            ReportMailPassword,
            ReportMailTo,
            ReportMailFrom,
            ReportMailServer,
            int(ReportMailPort),
        )

        return Method, EmailObj

    elif args.report == "webhook":
        Method = ReportType.WEBHOOK
        if args.report_webhook:
            Webhook = args.report_webhook
        else:
            Webhook = input("Enter your webhook URL: ")

        return Method, Webhook


def Confirmation(message) -> bool: #! fix this shit
    if DontAskForConfirmation:
        return True

    confirmation = input(message)
    return confirmation.lower() != "n"


def UserConfirmation() -> tuple[bool, bool, bool]: #! fix this shit
    if DontAskForConfirmation:
        return True, True, True

    portscan = Confirmation("Do you want to scan ports? [Y/n]: ")
    if not portscan:
        return False, False, False

    vulnscan = Confirmation(
            "Do you want to scan for vulnerabilities? [Y/n]: "
        )
    if not vulnscan:
        return True, False, False

    downloadexploits = Confirmation(
            "Do you want to download exploits? [Y/n]: "
        )

    return portscan, vulnscan, downloadexploits


def WebScan() -> bool: #! fix this shit
    return Confirmation(
        "Do you want to scan for web vulnerabilities? [Y/n]: "
    )


def GetHostsToScan(hosts, console) -> list[str]:
    if len(hosts) == 0:
        raise SystemExit(
            "No hosts found! {time} - Scan completed.".format(
                time=datetime.now().strftime("%b %d %Y %H:%M:%S")
            )
        )

    index: int = 0
    for host in hosts:
        if not len(host) % 2 == 0:
            host += " "

        msg = Text.assemble(
                (
                    "[",
                    "red"
                ),
                (
                    str(index),
                    "cyan"
                ),
                (
                    "] ", "red"
                ),
                host
            )
        console.print(msg, justify="center")

        index += 1

    if DontAskForConfirmation:
        return hosts

    console.print(
        (
            "\n[yellow]Enter the index number of the "
            "host you would like to enumurate further.\n"
            "Enter 'all' to enumurate all hosts.\n"
            "Enter 'exit' to exit [/yellow]"
        )
    )

    while True:
        host = input("-> ")
        Targets = hosts

        if host in hosts:
            Targets = [host]
        else:
            if host == "all" or host == "":
                break
            elif host == "exit":
                raise SystemExit(
                    "{time} - Scan completed."
                        .format(
                            time=(
                                    datetime
                                        .now()
                                        .strftime(
                                            "%b %d %Y %H:%M:%S"
                                        )
                                )
                        )
                )
            else:
                if int(host) < len(hosts) and int(host) >= 0:
                    Targets = [hosts[int(host)]]
                    break
                else:
                    console.print(
                        (
                            "Please enter a valid host"
                            "number or 'all' or 'exit'"
                        ),
                        style="red",
                    )

    return Targets


def InitArgsConf(args, log) -> None: #! fix this shit
    if not args.config:
        return

    try:
        config = ConfigParser()
        config.read(args.config)

        if config.has_option("AUTOPWN", "target"):
            args.target = (
                    config
                        .get(
                            "AUTOPWN",
                            "target"
                        )
                        .lower()
                )

        if config.has_option("AUTOPWN", "hostfile"):
            args.host_file = (
                    config
                        .get(
                            "AUTOPWN",
                            "hostfile"
                        )
                        .lower()
                )

        if config.has_option("AUTOPWN", "scantype"):
            args.scan_type = (
                    config
                        .get(
                            "AUTOPWN",
                            "scantype"
                        )
                        .lower()
                )

        if config.has_option("AUTOPWN", "nmapflags"):
            args.nmap_flags = (
                    config
                        .get(
                            "AUTOPWN",
                            "nmapflags"
                        )
                        .lower()
                )

        if config.has_option("AUTOPWN", "speed"):
            try:
                args.speed = int(config.get("AUTOPWN", "speed"))
            except ValueError:
                log.logger(
                    "error",
                    "Invalid speed value in config file. (Default: 3)"
                )

        if config.has_option("AUTOPWN", "apikey"):
            args.api = config.get("AUTOPWN", "apikey").lower()

        if config.has_option("AUTOPWN", "auto"):
            args.yes_please = True

        if config.has_option("AUTOPWN", "mode"):
            args.mode = config.get("AUTOPWN", "mode").lower()

        if config.has_option("AUTOPWN", "noisetimeout"):
            args.noise_timeout = config.get("AUTOPWN", "noisetimeout").lower()

        if config.has_option("REPORT", "output"):
            args.output = (
                    config
                        .get(
                            "REPORT",
                            "output"
                        )
                        .lower()
                )

        if config.has_option("REPORT", "outputtype"):
            args.output_type = (
                    config
                        .get(
                            "REPORT",
                            "outputtype"
                        )
                        .lower()
                    )

        if config.has_option("REPORT", "method"):
            args.report = (
                    config
                        .get(
                            "REPORT",
                            "method"
                        )
                        .lower()
                )

        if config.has_option("REPORT", "email"):
            args.report_email = (
                    config
                        .get(
                            "REPORT",
                            "email"
                        )
                        .lower()
                    )

        if config.has_option("REPORT", "email_password"):
            args.report_email_password = (
                    config
                        .get(
                            "REPORT",
                            "email_password"
                        )
                        .lower()
                )

        if config.has_option("REPORT", "email_to"):
            args.report_email_to = (
                    config
                        .get(
                            "REPORT",
                            "email_to"
                        )
                        .lower()
                )

        if config.has_option("REPORT", "email_from"):
            args.report_email_from = (
                    config
                        .get(
                            "REPORT",
                            "email_from"
                        )
                        .lower()
                )

        if config.has_option("REPORT", "email_server"):
            args.report_email_server = (
                    config
                        .get(
                            "REPORT",
                            "email_server"
                        )
                        .lower()
                )

        if config.has_option("REPORT", "email_port"):
            args.report_email_server_port = (
                    config
                    .get(
                        "REPORT",
                        "email_port"
                    )
                    .lower()
                )

        if config.has_option("REPORT", "webhook"):
            args.report_webhook = (
                    config
                        .get(
                            "REPORT",
                            "webhook"
                        )
                )

    except FileNotFoundError as err:
        raise SystemExit("Config file not found!") from err
    except PermissionError as err:
        raise SystemExit(
            (
                "Permission denied while"
                " trying to read config file!"
            )
        ) from err


def install_nmap_linux(log) -> None: #! fix this shit
    distro_: str = distro.id().lower()
    for _ in range(3):
        try:
            if distro_ in [
                "ubuntu",
                "debian",
                "linuxmint",
                "raspbian",
                "kali",
                "parrot",
            ]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "apt-get",
                        "install",
                        "nmap",
                        "-y"
                    ],
                    stderr=DEVNULL,
                )
            elif distro_ in ["arch", "manjaro"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "pacman",
                        "-S",
                        "nmap",
                        "--noconfirm"
                    ],
                    stderr=DEVNULL,
                )
            elif distro_ in ["fedora", "oracle"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "dnf",
                        "install",
                        "nmap",
                        "-y"
                    ],
                    stderr=DEVNULL
                )
            elif distro_ in ["rhel", "centos"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "yum",
                        "install",
                        "nmap",
                        "-y"
                    ],
                    stderr=DEVNULL
                )
            elif distro_ in ["sles", "opensuse"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "zypper",
                        "install",
                        "nmap",
                        "--non-interactive"
                    ],
                    stderr=DEVNULL,
                )
            else:
                raise CalledProcessError

        except CalledProcessError:
            _distro_ = input(
                (
                    "Cannot recognize the needed package manager for your "
                    f"system that seems to be running in: {distro_} and "
                    f"{sys_platform}, {platform()}, kindly select the correct"
                    " package manager below to proceed to the installation, else,"
                    " select, n.\n\t0 Abort installation\n\t1 apt-get\n\t2 dnf\n\t3"
                    " yum\n\t4 pacman\n\t5 zypper.\nSelect option [0-5] >"
                )
            )
            match _distro_:
                case 1:
                    distro_ = "ubuntu"
                case 2:
                    distro_ = "fedora"
                case 3:
                    distro_ = "centos"
                case 4:
                    distro_ = "arch"
                case 5:
                    distro_ = "opensuse"
                case _:
                    log.logger("error", "Couldn't install nmap (Linux)")
            continue
        else:
            break

def install_nmap_windows(log) -> None:
    try:
        check_call(
            [
                "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "winget",
                "install",
                "nmap",
                "--silent",
            ],
            stderr=DEVNULL,
        )
        log.logger(
            "warning", "Nmap is installed but shell restart is required."
        )
        raise SystemExit
    except CalledProcessError as err:
        raise SystemExit("Couldn't install nmap! (Windows)") from err


def install_nmap_mac(log) -> None:
    try:
        check_call(
            [
                "/usr/bin/sudo",
                "brew",
                "install",
                "nmap"
            ],
            stderr=DEVNULL
        )
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Mac)")


def check_nmap(log) -> None:
    try:
        check_call(
            ["nmap", "-h"],
            stdout=DEVNULL,
            stderr=DEVNULL
        )
    except (CalledProcessError, FileNotFoundError):
        log.logger("warning", "Nmap is not installed.")

        auto_install = True

        if not DontAskForConfirmation:
            auto_install = (
                input(
                    f"Install Nmap on your system ({system()})? "
                ).lower() != "n"
            )

        if not auto_install:
            raise SystemExit("Denied permission to install Nmap.")

        match system().lower():
            case "linux":
                install_nmap_linux(log)
            case "windows":
                install_nmap_windows(log)
            case "darwin":
                install_nmap_mac(log)
            case _:
                raise SystemExit(
                        "Unknown OS! Auto installation not supported!"
                    )


def ParamPrint( #! fix this shit
        args,
        targetarg: str,
        scantype_name: ScanType,
        scanmode_name: ScanMode,
        apiKey: str,
        console,
        log,
    ) -> None:

    if not is_root():
        log.logger(
            "warning",
            (
                "It is recommended to run this script as root"
                " since it is more silent and accurate."
            )
        )

    term_width: int = get_terminal_width()

    msg = (
        "\n┌─[ Scanning with the following parameters ]\n"
        + f"├"
        + "─" * (term_width - 1)
        + "\n"
        + f"│\tTarget: {targetarg}\n"
        + f"│\tOutput file: [yellow]{args.output}[/yellow]\n"
        + f"│\tAPI Key: {type(apiKey) == str}\n"
        + f"│\tAutomatic: {DontAskForConfirmation}\n"
    )

    if args.skip_discovery:
        msg += "│\tSkip discovery: True\n"

    if args.host_file:
        msg += f"│\tHostfile: {args.host_file}\n"

    if not args.host_timeout == 240:
        msg += f"│\tHost timeout: {args.host_timeout}\n"

    if scanmode_name == ScanMode.Normal:
        msg += (
            f"│\tScan type: [red]{scantype_name.name}[/red]\n"
            + f"│\tScan speed: {args.speed}\n"
        )
    elif scanmode_name == ScanMode.Evade:
        msg += (
            f"│\tScan mode: {scanmode_name.name}\n"
            + f"│\tScan type: [red]{scantype_name.name}[/red]\n"
            + f"│\tScan speed: {args.speed}\n"
        )
    elif scanmode_name == ScanMode.Noise:
        msg += f"│\tScan mode: {scanmode_name.name}\n"

    if not args.nmap_flags == None and not args.nmap_flags == "":
        msg += f"│\tNmap flags: [blue]{args.nmap_flags}[/blue]\n"

    if args.report:
        msg += f"│\tReporting method: {args.report}\n"

    msg += "└" + "─" * (term_width - 1)

    console.print(msg)


def CheckConnection(log) -> bool: #! fix this shit
    try:
        get("https://google.com", timeout=5)
    except Exception as e: #! fix this crap
        log.logger("error", "Connection failed.")
        log.logger("error", e)
        return False
    else:
        return True


def SaveOutput(console, out_type, output_file) -> None: #! fix this shit
    if out_type == "html":
        if not output_file.endswith(".html"):
            output_file += ".html"
        console.save_html(output_file)
    elif out_type == "svg":
        if not output_file.endswith(".svg"):
            output_file += ".svg"
        console.save_svg(output_file)
    elif out_type == "txt":
        console.save_text(output_file)


def get_terminal_width() -> int: #! fix this shit
    try:
        width, _ = get_terminal_size()
    except OSError:
        width = 80

    if system().lower() == "windows":
        width -= 1

    return width


def check_version(cur_version: str, log) -> None:
    try:
        data = get(
                "https://pypi.org/pypi/autopwn-suite/json", timeout=5
            ).json()
    except Exception as e: #! fix this crap
        log.logger(
            "error",
            (
                "An error occured while "
                "checking AutoPWN Suite version."
            )
        )
        log.logger("error", e)
    else:
        version = list(data["releases"].keys())[-1]
        version_major = int(version.split(".")[0])
        version_minor = int(version.split(".")[1])
        version_patch = int(version.split(".")[2])

        cur_version_major = int(cur_version.split(".")[0])
        cur_version_minor = int(cur_version.split(".")[1])
        cur_version_patch = int(cur_version.split(".")[2])

        if version_major > cur_version_major:
            log.logger(
                "warning",
                "Your version of AutoPWN Suite is outdated. Update is advised."
            )
        elif version_minor > cur_version_minor:
            log.logger(
                "warning",
                "Your version of AutoPWN Suite is outdated. Update is advised."
            )
        elif version_patch > cur_version_patch:
            log.logger(
                "warning",
                "Your version of AutoPWN Suite is outdated. Update is advised."
            )
