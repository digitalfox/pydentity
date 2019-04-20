######################################################################################
### Copy the file under the name mail_settings.py and customize with your settings ###
######################################################################################


# Flask Mail settings
MAIL_SERVER = "smtp.mydomain.net"
MAIL_PORT = 587
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = "mymail@mydomain.com"
MAIL_PASSWORD = "my_secret_password"
MAIL_DEFAULT_SENDER = ("Me", "mymail@mydomain.com")
MAIL_MAX_EMAILS = None
