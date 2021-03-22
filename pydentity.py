# coding: utf-8
"""
Mini application to manage apache htpasswd file
@author: Sébastien Renard (sebastien.renard@digitalfox.org)
@license: AGPL v3 or newer (http://www.gnu.org/licenses/agpl-3.0.html)
"""

import subprocess
import string
from os.path import dirname, join
from re import match

from flask import Flask, render_template, request, redirect, url_for
import htpasswd
import random


app = Flask(__name__)

# Configuration
CONF = {
    "PRODUCT_NAME": "My application",
    "PWD_FILE": join(dirname(__file__), "htpasswd"),
    "GROUP_FILE": join(dirname(__file__), "htgroup"),
    # Name of the admin group. User need to belong to this group to be able to change other user password
    # or create new user. REQUIRE_REMOTE_USER parameter is required
    "ADMIN_GROUP": "admin",
    # Whether to require http basic auth upstream (for example with apache)
    "REQUIRE_REMOTE_USER": True,
    # New password pattern regexp check. Note that this regexp must be compliant to both Python regexp syntax
    # and HTML 5 form pattern syntax
    "PASSWORD_PATTERN": "(?=.*\d)(?=.*[a-z])(?=.*[A-Z\!\@\#\$\%\^\&\*\-\+\;\?\.\!\_\=\(\)\[\]\{\}]).{8,}",
    # Clear text that explain to user the password requirements
    "PASSWORD_PATTERN_HELP": "Lower case, numeric and upper case or special char. At least 8 char",
    # List of used chars for password generation
    "PASSWORD_GENERATION_SPECIAL_CHAR": "!@#$%^&*+;?.!_=()[]{}",
    # Conf for the mailer
    "ENABLE_MAIL_CAPABILITIES": True,
    "MAIL_CONF": "mail_settings.py",
    # Deployment prefix - useful when behind reverse proxy
    # Don't put trailing slash. For no prefix, use an empty string
    "URL_PREFIX": "",
}
app.config["PYDENTITY_URL_PREFIX"] = CONF["URL_PREFIX"]


# Load all module and config for mailing capabilities
if CONF["ENABLE_MAIL_CAPABILITIES"]:
    from flask_mail import Mail, Message

    try:
        app.config.from_pyfile(CONF["MAIL_CONF"])
    except:
        print("WARNING: unable to find config file %s. Disabling email capabilities" % CONF["MAIL_CONF"])
        CONF["ENABLE_MAIL_CAPABILITIES"] = False
    mail = None


@app.route(CONF["URL_PREFIX"] + "/")
def home():
    if not get_remote_user(request):
        # No REMOTE_USER header, can't work
        message = "Can't work without REMOTE_USER header, contact an administrator"
        return render_template("message.html", success=False, message=message)

    url = url_for("user", username=get_remote_user(request))
    if "return_to" in request.args:
        url += "?return_to=%s" % request.args.get("return_to")
    return redirect(url)


@app.route(CONF["URL_PREFIX"] + "/list_users")
def list_users():
    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        is_admin, admin_error_message = check_user_is_admin(get_remote_user(request))
        if not is_admin:
            # User is not admin, can't allow
            return render_template("message.html", message=admin_error_message)
        return render_template("list_users.html", is_admin=is_admin, users=userdb.users)


@app.route(CONF["URL_PREFIX"] + "/list_groups")
def list_groups():
    is_admin, admin_error_message = check_user_is_admin(get_remote_user(request))
    if not is_admin:
        # User is not admin, can't allow
        return render_template("message.html", message=admin_error_message)

    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
            groups = dict()
            for user in userdb.users:
                for group in groupdb.groups:
                    if group not in groups:
                        groups[group] = []
                    if groupdb.is_user_in(user, group):
                        groups[group].append(user)

    return render_template("list_groups.html", is_admin=is_admin, groups=groups)


@app.route(CONF["URL_PREFIX"] + "/user", methods=["POST", "GET"])
def user_entrypoint():
    """Simple user entrypoint to redirect to the correct user page"""
    if CONF["REQUIRE_REMOTE_USER"]:
        if not get_remote_user(request):
            return render_template("message.html", message="Sorry, you must be logged with http basic auth to go here")
        else:
            url = url_for("user", username=get_remote_user(request))
            return redirect(url)


@app.route(CONF["URL_PREFIX"] + "/user/<username>", methods=["POST", "GET"])
def user(username):
    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:

        new_user = username not in userdb
        is_admin, admin_error_message = check_user_is_admin(get_remote_user(request))

        if CONF["REQUIRE_REMOTE_USER"]:
            if not get_remote_user(request):
                return render_template(
                    "message.html", message="Sorry, you must be logged with http basic auth to go here"
                )
            if get_remote_user(request) != username or new_user:
                # User trying to change someone else password
                if not is_admin:
                    # User is not admin or admin group does exist. Ciao
                    return render_template("message.html", message=admin_error_message)

        with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
            groups = dict()
            for group in groupdb.groups:
                if groupdb.is_user_in(username, group):
                    groups[group] = True
                else:
                    groups[group] = False

        if request.method == "GET":
            return render_template(
                "user.html",
                username=username,
                new=new_user,
                is_admin=is_admin,
                groups=groups,
                password_pattern=CONF["PASSWORD_PATTERN"],
                password_pattern_help=CONF["PASSWORD_PATTERN_HELP"],
            )
        else:
            # POST Request
            success = True
            message = ""
            message_details = ""

            if (
                "generaterandom" in request.form
                or request.form["new_password"] != ""
                or request.form["repeat_password"] != ""
            ):
                # Then the user wanted to generate a new password (chosen or random)

                # All failure conditions
                if "generaterandom" not in request.form:
                    if request.form["new_password"] != request.form["repeat_password"]:
                        message = "Passwords differ. Please try again"
                        success = False
                    if not match(CONF["PASSWORD_PATTERN"], request.form["new_password"]):
                        message = "New password does not match requirements (%s)" % CONF["PASSWORD_PATTERN_HELP"]
                        success = False
                    if not is_admin and not check_password(userdb.new_users[username], request.form["old_password"]):
                        message = "Old password does not match"
                        success = False
                    if request.form["new_password"] == "":
                        message = "New password it required. Please try again."
                        success = False
                    if request.form["repeat_password"] == "":
                        message = "Repeated password it required. Please try again."
                        success = False

                if success == False:
                    return render_template(
                        "user.html",
                        username=username,
                        new=new_user,
                        is_admin=is_admin,
                        groups=groups,
                        password_pattern=CONF["PASSWORD_PATTERN"],
                        password_pattern_help=CONF["PASSWORD_PATTERN_HELP"],
                        message=message,
                        success=success,
                    )

                # If the generate random password is checked
                if "generaterandom" in request.form:
                    new_password = generate_random_password()
                    message_details = "Generated random password is: %s" % new_password
                else:
                    new_password = request.form["new_password"]
                    message_details = "Password set to chosen password"

                if new_user:
                    userdb.add(username, new_password)
                    message = "User created with random password"
                else:
                    userdb.change_password(username, new_password)
                    message = "User password updated"

            # Process groups, only for admin user
            message_groups = ""
            message_groups_details = ""
            if is_admin:
                with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
                    checked_groups = [g.split("_", 1)[1] for g in list(request.form.keys()) if g.startswith("group_")]
                    message_groups_details = ""
                    for group in groupdb.groups:
                        if group in checked_groups:
                            if not groupdb.is_user_in(username, group):
                                groupdb.add_user(username, group)
                                groups[group] = True
                                message_groups_details += "add " + group + ", "
                        else:
                            if groupdb.is_user_in(username, group):
                                groupdb.delete_user(username, group)
                                groups[group] = False
                                message_groups_details += "delete " + group + ", "
                    if message_groups_details:
                        message_groups = "User groups changed"
                        message_groups_details = "Changed groups are: " + message_groups_details[:-2]

            if request.args.get("return_to"):
                return redirect(request.args.get("return_to"))
            else:
                return render_template(
                    "user.html",
                    username=username,
                    new=new_user,
                    is_admin=is_admin,
                    groups=groups,
                    password_pattern=CONF["PASSWORD_PATTERN"],
                    password_pattern_help=CONF["PASSWORD_PATTERN_HELP"],
                    message=message,
                    message_details=message_details if message_details else None,
                    message_groups=message_groups,
                    message_groups_details=message_groups_details,
                    success=True,
                )


@app.route(CONF["URL_PREFIX"] + "/group/<group>", methods=["POST", "GET"])
def group(group):
    is_admin, admin_error_message = check_user_is_admin(get_remote_user(request))
    if not is_admin:
        # User is not admin, can't allow
        return render_template("message.html", message=admin_error_message)

    message = ""
    if request.method == "POST":
        # If the user clicked the "Remove a user" button
        user_to_remove = [g.split("_", 1)[1] for g in list(request.form.keys()) if g.startswith("remove_")]
        if user_to_remove:
            user_to_remove = user_to_remove[0]
            with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
                if groupdb.is_user_in(user_to_remove, group):
                    groupdb.delete_user(user_to_remove, group)
                    message = "User %s removed from group %s" % (user_to_remove, group)

        # If the user clicked the "Add a user" button
        if "add_user_to_group" in request.form:
            with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
                groupdb.add_user(request.form["select_user"], group)
                message = "User %s added to group %s" % (request.form["select_user"], group)

    users = []
    possible_users = []
    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
            for user in userdb.users:
                if groupdb.is_user_in(user, group):
                    users.append(user)
                else:
                    possible_users.append(user)

    return render_template(
        "group.html", message=message, is_admin=is_admin, group=group, users=users, possible_users=possible_users
    )


@app.route(CONF["URL_PREFIX"] + "/batch_user_creation", methods=["POST", "GET"])
def batch_user_creation():

    is_admin, message = check_user_is_admin(get_remote_user(request))
    if not is_admin:
        # User is not admin or admin group does exist. Ciao
        return render_template("message.html", message=message)

    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
            if request.method == "GET":
                groups = []
                for group in groupdb.groups:
                    groups.append(group)
                return render_template(
                    "batch_user_creation.html",
                    is_admin=is_admin,
                    groups=groups,
                    mail_capabilities=CONF["ENABLE_MAIL_CAPABILITIES"],
                )
            else:
                # POST Request
                users = request.form["users_login"].split("\r\n")
                checked_groups = [g.split("_", 1)[1] for g in list(request.form.keys()) if g.startswith("group_")]
                result = []
                for username in users:
                    new_password = generate_random_password()
                    new_user = username not in userdb
                    if new_user:
                        userdb.add(username, new_password)
                        action = "create"
                    else:
                        userdb.change_password(username, new_password)
                        action = "update"
                    result.append((username, new_password, action))
                    for group in groupdb.groups:
                        if group in checked_groups:
                            if not groupdb.is_user_in(username, group):
                                groupdb.add_user(username, group)
                        else:
                            if groupdb.is_user_in(username, group):
                                groupdb.delete_user(username, group)
                message = "Batch of user created with generated passwords"

                # If the "send_mail" checkbox is enabled
                if request.form.get("send_mail") is not None:
                    message = "Batch of user created with generated passwords, a mail has been sent to all of them"
                    send_mail(result, request.form["mail_suffix"], request.form["instance"])

                return render_template(
                    "message.html",
                    message=message,
                    success=True,
                    result=render_template("result_template.html", is_admin=is_admin, result=result),
                )


def check_user_is_admin(user):
    """Ensure username is in admin group and that admin group exists
    @:return: tuple (result, message), result is True if user is admin, else False. message indicate reason if False"""
    with htpasswd.Group(CONF["GROUP_FILE"]) as groupsdb:
        if CONF["ADMIN_GROUP"] not in groupsdb:
            return (
                False,
                "Sorry admin group '%s' is not defined. You cannot change someone else password or create new user"
                % CONF["ADMIN_GROUP"],
            )
        if not groupsdb.is_user_in(user, CONF["ADMIN_GROUP"]):
            return (
                False,
                "Forbidden: only admin user allowed",
            )
        # Everything is fine
        return (True, "")


def check_password(encrypted_passwd, clear_passwd, mode="md5"):
    """check that password is correct against its hash
    TODO: propose to python-htpasswd to integrate this code in his lib"""
    salt = encrypted_passwd.split("$")[2]  # Extract salt from current encrypted password
    new_encrypted_passwd = subprocess.check_output(["openssl", "passwd", "-apr1", "-salt", salt, clear_passwd]).decode(
        "utf-8"
    )
    return encrypted_passwd == new_encrypted_passwd


def generate_random_password(length=10):
    """Generate a random password of the desired length, with 1 number, 1 upper case, 1 special char minimum
    @return a generated password of the desired length"""
    number = random.sample(string.digits, 1)
    lowercase = random.sample(string.ascii_lowercase, 1)
    uppercase = random.sample(string.ascii_uppercase, 1)
    specialchar = random.sample(CONF["PASSWORD_GENERATION_SPECIAL_CHAR"], 1)
    others = random.sample(
        string.digits + string.ascii_lowercase + string.ascii_uppercase + CONF["PASSWORD_GENERATION_SPECIAL_CHAR"],
        length - 4,
    )
    bag = number + specialchar + lowercase + uppercase + others
    random.shuffle(bag)
    return "".join(bag)


def send_mail(result, mail_suffix, instance):
    """Send a mail to the users with their newly created/updated password"""
    for username, password, action in result:
        mail = get_mail()
        with mail.connect() as conn:
            user_mail = username
            if mail_suffix is not None:
                user_mail = user_mail + mail_suffix

            body = render_template(
                "mail.html",
                username=username,
                password=password,
                action=action,
                produit=CONF["PRODUCT_NAME"],
                instance=instance,
            )
            subject = "Votre accès à %s" % CONF["PRODUCT_NAME"]

            message = Message(body=body, subject=subject, recipients=[user_mail])
            conn.send(message)


def get_mail():
    """@return an instance of the mail class"""
    return Mail(app)


def get_remote_user(request):
    """uniform way to get remote user. flask/werkzeurg default is sensitive to - / _ and case..."""
    if request.remote_user:
        return request.remote_user
    elif request.headers.get("Remote-User"):
        return request.headers["Remote-User"]
    else:
        return None


if __name__ == "__main__":
    app.debug = True
    app.run()
