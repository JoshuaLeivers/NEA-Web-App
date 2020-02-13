from werkzeug.exceptions import HTTPException


# Python Errors
class Error(Exception):
    """Base class for exceptions in this app."""

    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)

    def __repr__(self):
        return self.message

    __str__ = __repr__


class ConfigSectionError(Error):
    """Exception raised when configparser cannot find a given section.

    Attributes:
        section -- section which configparser could not find
    """

    def __init__(self, section):
        Error.__init__(self, section + " section in config does not exist. Please configure "
                       + section + ". Resetting to defaults.")
        self.section = section
        self.args = (section,)


class ConfigOptionError(Error):
    """Exception raised when configparser cannot find a given option.

    Attributes:
        option -- option which configparser cannot find
        section -- section which the option should be in
    """

    def __init__(self, option, section):
        Error.__init__(self,
                       option + " missing from " + section + " section. Please configure " + section + "settings. "
                                                                                                       "Resetting to "
                                                                                                       "default.")
        self.option = option
        self.section = section
        self.args = (option, section)


class ConfigInvalidValueError(Error):
    """Exception raised when a config value is invalid.

    Attributes:
        key -- the config key whose value is invalid
    """

    def __init__(self, options, section):
        Error.__init__(self, ", ".join(
            options) + " given in " + section + " section of config.ini is invalid")
        self.options = options
        self.section = section
        self.args = (options, section)


# HTTP Errors
class InvalidUser(HTTPException):
    code = 404
    description = "This user does not exist."
