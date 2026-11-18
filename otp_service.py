import os
import smtplib
from email.message import EmailMessage


def send_otp(user, code):
    if not user.email:
        return False

    required = ["MAIL_SERVER", "MAIL_PORT", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_FROM"]
    missing = [key for key in required if not os.environ.get(key)]

    if missing:
        print("SMTP CONFIG MISSING:", ", ".join(missing))
        return False

    message = EmailMessage()
    message["Subject"] = "NET BOOK Account Verification"
    message["From"] = os.environ["MAIL_FROM"]
    message["To"] = user.email
    message.set_content(
        f"আপনার NET BOOK verification code: {code}\n"
        "এই কোড ১০ মিনিটের মধ্যে ব্যবহার করুন। "
        "কাউকে এই কোড দেবেন না।"
    )

    try:
        with smtplib.SMTP(
            os.environ["MAIL_SERVER"],
            int(os.environ["MAIL_PORT"]),
            timeout=20
        ) as smtp:
            smtp.starttls()
            smtp.login(
                os.environ["MAIL_USERNAME"],
                os.environ["MAIL_PASSWORD"].replace(" ", "")
            )
            refused = smtp.send_message(message)

            if refused:
                print("SMTP RECIPIENT REJECTED")
                return False

            print("SMTP ACCEPTED: Recipient server accepted the message.")
            return True

    except Exception as exc:
        print("SMTP ERROR:", type(exc).__name__)
        print("SMTP CODE:", getattr(exc, "smtp_code", "N/A"))
        return False
