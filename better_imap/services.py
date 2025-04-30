from .models import ServiceType
from enum import Enum


class Service:
    RAMBLER = ServiceType(
        name="Rambler",
        host="imap.rambler.ru",
        folders=["INBOX", "Spam"],
    )
    OUTLOOK = ServiceType(
        name="Outlook",
        host="outlook.office365.com",
        folders=["INBOX"],
    )
    ICLOUD = ServiceType(
        name="iCloud",
        host="imap.mail.me.com",
        folders=["INBOX"],
    )
    GMAIL = ServiceType(
        name="Gmail",
        host="imap.gmail.com",
        folders=["INBOX", "Spam"],
    )
    MAILRU = ServiceType(
        name="Mail.ru",
        host="imap.mail.ru",
        folders=["INBOX", "Spam"],
    )
    FIRSTMAIL = ServiceType(
        name="Firstmail",
        host="imap.firstmail.ltd",
        folders=["INBOX"],
    )


DOMAIN_TO_SERVICE = {
    "@rambler.ru": Service.RAMBLER,
    "@ro.ru": Service.RAMBLER,
    "@myrambler.ru": Service.RAMBLER,
    "@autorambler.ru": Service.RAMBLER,
    "@hotmail.com": Service.OUTLOOK,
    "@outlook.com": Service.OUTLOOK,
    "@icloud.com": Service.ICLOUD,
    "@gmail.com": Service.GMAIL,
    "@mail.ru": Service.MAILRU,
    "@inbox.ru": Service.MAILRU,
    "@bk.ru": Service.MAILRU,
    "@list.ru": Service.MAILRU,
    "@firstmail.ltd": Service.FIRSTMAIL,
    "@firstmail.ru": Service.FIRSTMAIL,
    "@nietamail.com": Service.FIRSTMAIL,
    "@menormail.com": Service.FIRSTMAIL,
    "@senoramail.com": Service.FIRSTMAIL,
    "@historiogramail.com": Service.FIRSTMAIL,
    "@ambismail.com": Service.FIRSTMAIL,
    "@andromomail.com": Service.FIRSTMAIL,
    "@superocomail.com": Service.FIRSTMAIL,
    "@velismail.com": Service.FIRSTMAIL,
    "@veridicalmail.com": Service.FIRSTMAIL,
    "@epidemiosmail.ru": Service.FIRSTMAIL,
    "@encepsmail.ru": Service.FIRSTMAIL,
    "@reevalmail.com": Service.FIRSTMAIL,
    "@decortiomail.ru": Service.FIRSTMAIL,
    "@decomposaomail.ru": Service.FIRSTMAIL,
    "@custoomail.ru": Service.FIRSTMAIL,
    "@diplofml.com": Service.FIRSTMAIL,
    "@cephafml.com": Service.FIRSTMAIL,
    "@opercfml.com": Service.FIRSTMAIL,
    "@deinstitutionalizaml.com": Service.FIRSTMAIL,
    "@methanomml.com": Service.FIRSTMAIL,
    "@paraprocml.com": Service.FIRSTMAIL,
    "@barothermohygfml.com": Service.FIRSTMAIL,
    "@nonsubmfml.com": Service.FIRSTMAIL,
    "@hydrofml.com": Service.FIRSTMAIL,
    "@menfml.com": Service.FIRSTMAIL,
}
