class BetterImapException(Exception):
    pass


class IMAPLoginFailed(BetterImapException):
    def __init__(self):
        super().__init__(f"IMAP disabled or account banned or incorrect login/password")


class IMAPSearchTimeout(BetterImapException):
    pass
