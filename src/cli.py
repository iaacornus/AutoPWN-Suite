from argparse import ArgumentParser


def cli():
    argparser = ArgumentParser(
        description=(
            "AutoPWN Suite | A project for scanning "
            "vulnerabilities and exploiting systems automatically."
        )
    )
    argparser.add_argument(
        "-v", "--version",
        help="Print version and exit.",
        action="store_true"
    )
    argparser.add_argument(
        "-y", "--yes-please",
        help="Don't ask for anything. (Full automatic mode)",
        action="store_true",
        required=False,
        default=False,
    )
    argparser.add_argument(
        "-c", "--config",
        help="Specify a config file to use. (Default: None)",
        default=None,
        required=False,
        metavar="CONFIG",
        type=str,
    )
    argparser.add_argument(
        "-nc", "--no-color",
        help="Disable colors.",
        default=False,
        required=False,
        action="store_true",
    )

    scanargs = argparser.add_argument_group("Scanning", "Options for scanning")
    scanargs.add_argument(
        "-t", "--target",
        help=(
            "Target range to scan. This argument overwrites the"
            " hostfile argument. (192.168.0.1 or 192.168.0.0/24)"
        ),
        type=str,
        required=False,
        default=None,
    )
    scanargs.add_argument(
        "-hf", "--host-file",
        help="File containing a list of hosts to scan.",
        type=str,
        required=False,
        default=None,
    )
    scanargs.add_argument(
        "-sd", "--skip-discovery",
        help="Skips the host discovery phase.",
        required=False,
        default=False,
        action="store_true",
    )
    scanargs.add_argument(
        "-st", "--scan-type",
        help="Scan type.",
        type=str,
        required=False,
        default=None,
        choices=["arp", "ping"],
    )
    scanargs.add_argument(
        "-nf", "--nmap-flags",
        help=(
            "Custom nmap flags to use for portscan."
            " (Has to be specified: -nf='-O')"
        ),
        default="",
        type=str,
        required=False,
    )
    scanargs.add_argument(
        "-s", "--speed",
        help="Scan speed. (Default: 3)",
        default=3,
        type=int,
        required=False,
        choices=range(0, 6),
    )
    scanargs.add_argument(
        "-ht", "--host-timeout",
        help="Timeout for every host. (Default: 240)",
        default=240,
        type=int,
        required=False,
    )
    scanargs.add_argument(
        "-a", "--api",
        help=(
            "Specify API key for vulnerability detection "
            + "for faster scanning. (Default: None)"
        ),
        default=None,
        type=str,
        required=False,
    )
    scanargs.add_argument(
        "-m", "--mode",
        help="Scan mode.",
        default="normal",
        type=str,
        required=False,
        choices=["evade", "noise", "normal"],
    )
    scanargs.add_argument(
        "-nt", "--noise-timeout",
        help="Noise mode timeout.",
        default=None,
        type=int,
        required=False,
        metavar="TIMEOUT",
    )

    reportargs = argparser.add_argument_group(
            "Reporting", "Options for reporting"
        )
    reportargs.add_argument(
        "-o", "--output",
        help="Output file name. (Default: autopwn.log)",
        default="autopwn",
        type=str,
        required=False,
    )
    reportargs.add_argument(
        "-ot", "--output-type",
        help="Output file type. (Default: html)",
        default="html",
        type=str,
        required=False,
        choices=["html", "txt", "svg"],
    )
    reportargs.add_argument(
        "-rp", "--report",
        help="Report sending method.",
        type=str,
        required=False,
        default=None,
        choices=["email", "webhook"],
    )
    reportargs.add_argument(
        "-rpe", "--report-email",
        help="Email address to use for sending report.",
        type=str,
        required=False,
        default=None,
        metavar="EMAIL",
    )
    reportargs.add_argument(
        "-rpep", "--report-email-password",
        help="Password of the email report is going to be sent from.",
        type=str,
        required=False,
        default=None,
        metavar="PASSWORD",
    )
    reportargs.add_argument(
        "-rpet", "--report-email-to",
        help="Email address to send report to.",
        type=str,
        required=False,
        default=None,
        metavar="EMAIL",
    )
    reportargs.add_argument(
        "-rpef", "--report-email-from",
        help="Email to send from.",
        type=str,
        required=False,
        default=None,
        metavar="EMAIL",
    )
    reportargs.add_argument(
        "-rpes", "--report-email-server",
        help="Email server to use for sending report.",
        type=str,
        required=False,
        default=None,
        metavar="SERVER",
    )
    reportargs.add_argument(
        "-rpesp", "--report-email-server-port",
        help="Port of the email server.",
        type=int,
        required=False,
        default=None,
        metavar="PORT",
    )
    reportargs.add_argument(
        "-rpw", "--report-webhook",
        help="Webhook to use for sending report.",
        type=str,
        required=False,
        default=None,
        metavar="WEBHOOK",
    )

    return argparser.parse_args()
