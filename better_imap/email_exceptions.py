class BaseEmailException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class EmailConnectionError(BaseEmailException):
    def __init__(self, *args):
        super().__init__(*args)


class EmailFolderSelectionError(BaseEmailException):
    def __init__(self, *args):
        super().__init__(*args)


class EmailLoginError(BaseEmailException):
    def __init__(self, *args):
        super().__init__(*args)


class EmailBannedOrCredentialsWrongOrImapOffError(EmailLoginError):
    def __init__(self, *args):
        super().__init__(*args)


class EmailSearchTimeout(BaseEmailException):
    def __init__(self, *args):
        super().__init__(*args)
