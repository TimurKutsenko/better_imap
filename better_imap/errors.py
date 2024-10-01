class BetterImapException(Exception):
    pass


class IMAPLoginFailed(BetterImapException):
    pass


class IMAPSearchTimeout(BetterImapException):
    pass
