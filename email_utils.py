import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

import constants


def generate_token():
    """Generate a secure, unique token."""
    return secrets.token_urlsafe(32)


def save_token_in_redis(redis_client, token, user_email, target_mac, expiration_minutes=15):
    """
    Store token details in Redis.
    """
    token_key = f"token:{token}"
    expiration_time = datetime.utcnow() + timedelta(minutes=expiration_minutes)
    redis_client.hmset(token_key, {
        constants.store_key_email: user_email,
        constants.store_key_mac_id: target_mac,
    })
    redis_client.expire(token_key, expiration_time)
    print(f"Stored token {token} in Redis.")


def read_esmtprc(file_path="/home/vishnu/.esmtprc"):
    """
    Read SMTP configuration from .esmtprc file with the custom format.
    """
    smtp_config = {}

    with open(file_path, "r") as f:
        for line in f:

            line = line.strip()
            if not line or line.startswith("#"):
                continue

            key, value = line.split(" ", 1)
            key = key.strip().lower()
            value = value.strip().strip('"')
            smtp_config[key] = value

    hostname = smtp_config.get("hostname", "")
    if ":" in hostname:
        smtp_server, smtp_port = hostname.split(":", 1)
        smtp_config["smtp_server"] = smtp_server
        smtp_config["smtp_port"] = int(smtp_port)
    else:
        smtp_config["smtp_server"] = hostname
        smtp_config["smtp_port"] = 25

    smtp_config["use_tls"] = smtp_config.get("starttls", "").lower() == "required"
    return smtp_config


def send_email(user_email, approval_link, target_mac):
    """Send the approval link via email."""
    email_message = EmailMessage()
    email_message["Subject"] = "One-Time Approval Link"
    email_message["From"] = "wificonnections@gectcr.ac.in"  # FIXME
    email_message["To"] = user_email
    email_message.set_content(
        f"Click the link to approve: {approval_link}. Please make sure that your mac address is {target_mac}")

    smtp_config = read_esmtprc()
    smtp_server = smtp_config["smtp_server"]
    smtp_port = smtp_config["smtp_port"]
    username = smtp_config["username"]
    password = smtp_config["password"]
    use_tls = smtp_config["use_tls"]

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        if use_tls:
            server.starttls()
        server.login(username, password)
        server.send_message(email_message)


def send_approval_link(redis_client, admission_number, target_mac):
    """Generate and send a one-time approval link."""
    token = generate_token()
    user_email = f"{admission_number}@gectcr.ac.in"

    # server_url = "https://gectcr.ac.in"
    server_url = "http://127.0.0.1:5000"  # debug

    save_token_in_redis(redis_client, token, user_email, target_mac)

    approval_link = f"{server_url}/wificonnections/approve?token={token}"

    # send_email(user_email, approval_link, target_mac) # FIXME: debug safety!
    print(f"Approval link sent to {user_email}: {approval_link}")
