import configparser

from defaults import defaults

config = configparser.ConfigParser()
config.read("config.ini")

config["Database"] = defaults["Database"]
config["Email"] = defaults["Email"]
config["Limits"] = defaults["Limits"]

with open("config.ini", "w") as configfile:
    config.write(configfile)
