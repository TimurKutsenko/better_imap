from .models import Service


RAMBLER = Service(
    name="Rambler",
    host="imap.rambler.ru",
    folders=["INBOX", "Spam"],
)
OUTLOOK = Service(
    name="Outlook",
    host="outlook.office365.com",
    folders=["INBOX"],
)
ICLOUD = Service(
    name="iCloud",
    host="imap.mail.me.com",
    folders=["INBOX"],
)
GMAIL = Service(
    name="Gmail",
    host="imap.gmail.com",
    folders=["INBOX", "Spam"],
)
MAILRU = Service(
    name="Mail.ru",
    host="imap.mail.ru",
    folders=["INBOX", "Spam"],
)
FIRSTMAIL = Service(
    name="Firstmail",
    host="imap.firstmail.ltd",
    folders=["INBOX"],
)


DOMAIN_TO_SERVICE = {
    "@rambler.ru": RAMBLER,
    "@ro.ru": RAMBLER,
    "@myrambler.ru": RAMBLER,
    "@autorambler.ru": RAMBLER,
    "@hotmail.com": OUTLOOK,
    "@outlook.com": OUTLOOK,
    "@icloud.com": ICLOUD,
    "@gmail.com": GMAIL,
    "@mail.ru": MAILRU,
    "@inbox.ru": MAILRU,
    "@bk.ru": MAILRU,
    "@list.ru": MAILRU,
    "@firstmail.ltd": FIRSTMAIL,
    "@firstmail.ru": FIRSTMAIL,
    "@nietamail.com": FIRSTMAIL,
    "@menormail.com": FIRSTMAIL,
    "@senoramail.com": FIRSTMAIL,
    "@historiogramail.com": FIRSTMAIL,
    "@ambismail.com": FIRSTMAIL,
    "@andromomail.com": FIRSTMAIL,
    "@superocomail.com": FIRSTMAIL,
    "@velismail.com": FIRSTMAIL,
    "@veridicalmail.com": FIRSTMAIL,
    "@epidemiosmail.ru": FIRSTMAIL,
    "@encepsmail.ru": FIRSTMAIL,
    "@reevalmail.com": FIRSTMAIL,
    "@decortiomail.ru": FIRSTMAIL,
    "@decomposaomail.ru": FIRSTMAIL,
    "@custoomail.ru": FIRSTMAIL,
    "@curviomail.ru": FIRSTMAIL,
}
