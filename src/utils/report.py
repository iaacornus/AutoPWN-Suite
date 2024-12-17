from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from os import remove
from smtplib import SMTP

from requests import post


class ReportType(Enum):
    """
    Enum for report types.
    """

    NONE = 0
    EMAIL = 1
    webhook = 2


@dataclass()
class ReportMail:
    """
    Report mail.
    """

    email: str
    password: str
    email_to: str
    email_from: str
    server: str
    port: int


def initialize_email_report(email_obj, log, console) -> None:
    """
    Initialize email report.
    """
    email = email_obj.email
    password = email_obj.password
    email_to = email_obj.email_to
    email_from = email_obj.email_from
    server = email_obj.server
    port = email_obj.port

    console.save_html("tmp_report.html")

    log.logger("info", "Sending email report...")

    send_email(
        email,
        password,
        email_to,
        email_from,
        server,
        port,
        log
    )

    remove("tmp_report.html")


def send_email(
        email,
        password,
        email_to,
        email_from,
        server,
        port,
        log
    ) -> None:
    """
    Send email report.
    """

    # Since google disabled sending emails via
    # smtp, i didn't have an opportunity to test
    # please create an issue if you test this
    msg = MIMEMultipart()
    msg["From"] = email_from
    msg["To"] = email_to
    msg["Subject"] = "AutoPWN Report"

    body = "AutoPWN Report"
    msg.attach(MIMEText(body, "plain"))

    html = open("tmp_report.html", "rb").read()
    part = MIMEText(html, "text/html")
    msg.attach(part)

    mail = SMTP(server, port)
    mail.starttls()
    mail.login(email, password)
    text = msg.as_string()
    mail.sendmail(email, email_to, text)
    mail.quit()
    log.logger("success", "Email report sent successfully.")


def initialize_webhook_report(webhook, log, console) -> None:
    """
    Initialize webhook report.
    """
    log.logger("info", "Sending webhook report...")
    console.save_text("report.log")
    send_webhook(webhook, log)
    remove("report.log")


def send_webhook(url, log) -> None:
    """
    Send webhook report.
    """
    file = open("report.log", "r", encoding="utf-8")
    payload = {"payload": file}

    try:
        req = post(url, files=payload, timeout=5)
        file.close()
        if req.status_code == 200:
            log.logger("success", "webhook report sent succesfully.")
        else:
            log.logger("error", "webhook report failed to send.")
            print(req.text)
    except Exception as e: #! use other exception
        log.logger("error", e)
        log.logger("error", "webhook report failed to send.")


def initialize_report(method, report_object, log, console) -> None:
    """
    Initialize report.
    """
    if method == ReportType.EMAIL:
        initialize_email_report(report_object, log, console)
    elif method == ReportType.webhook:
        initialize_webhook_report(report_object, log, console)
