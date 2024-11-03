from email.message import Message
import re
import html2text
from better_imap.models import Service
from better_imap.services import DOMAIN_TO_SERVICE

text_maker = html2text.HTML2Text()
text_maker.ignore_links = False

def get_service_by_email_address(email_address: str) -> Service:
    domain = "@" + email_address.split("@")[1]

    if domain not in DOMAIN_TO_SERVICE:
        raise ValueError(f"Unknown mail domain: {domain}")

    return DOMAIN_TO_SERVICE[domain]


def clean_text(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\n\s*\n", "\n", text)
    lines = text.split("\n")
    lines = [line.strip() for line in lines if line.strip()]
    cleaned_text = "\n".join(lines)
    return cleaned_text


def extract_email_text(message: Message):
    text_content = None
    html_content = None

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                continue

            if content_type == "text/plain":
                charset = part.get_content_charset() or "utf-8"
                text_content = part.get_payload(decode=True).decode(
                    charset, errors="replace"
                )
            elif content_type == "text/html":
                charset = part.get_content_charset() or "utf-8"
                html_content = part.get_payload(decode=True).decode(
                    charset, errors="replace"
                )
    else:
        content_type = message.get_content_type()
        charset = message.get_content_charset() or "utf-8"

        if content_type == "text/plain":
            text_content = message.get_payload(decode=True).decode(
                charset, errors="replace"
            )
        elif content_type == "text/html":
            html_content = message.get_payload(decode=True).decode(
                charset, errors="replace"
            )

    if text_content and text_content.strip():
        cleaned_text = clean_text(text_content)
        return cleaned_text
    elif html_content:
        cleaned_text = text_maker.handle(html_content)
        # cleaned_text = clean_text(text)
        return cleaned_text
    else:
        return ""
