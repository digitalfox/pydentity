# coding: utf-8
"""
Mini application to manage apache htpasswd file
@author: Sébastien Renard (sebastien.renard@digitalfox.org)
@license: AGPL v3 or newer (http://www.gnu.org/licenses/agpl-3.0.html)
"""

import subprocess
from os.path import dirname, join
from re import match

from flask import Flask, render_template, request, redirect, url_for
import htpasswd
import random


app = Flask(__name__)

# Configuration
CONF = {
    "PWD_FILE": join(dirname(__file__), "htpasswd"),
    "GROUP_FILE" : join(dirname(__file__), "htgroup"),
    # Name of the admin group..User need to belong to this group to be able to change other user password or create new user. REQUIRE_REMOTE_USER parameter is required
    "ADMIN_GROUP" : "admin",
    # Whether to require http basic auth upstream (for example with apache)
    "REQUIRE_REMOTE_USER": True,
    # New password pattern regexp check. Note that this regexp must be compliant to both Python regexp syntax and HTML 5 form pattern syntax
    "PASSWORD_PATTERN": "(?=.*\d)(?=.*[a-z])(?=.*[A-Z\!\@\#\$\%\^\&\*\-\+\;\?\.\!\_\=\(\)\[\]\{\}]).{8,}",
    # Clear text that explain to user the password requirements
    "PASSWORD_PATTERN_HELP" : "Upper and lower case, numeric. At least 8 char",
    # List of used chars for password generation
    "PASSWORD_GENERATION_CHARS": "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*-+;?.!_=()[]{}"
}


@app.route("/")
def home():
    if "REMOTE_USER" in request.headers:
        url = url_for("user", username=request.headers["REMOTE_USER"])
        if "return_to" in request.args:
            url += "?return_to=%s" % request.args.get("return_to")
    else:
        url = url_for("list_users")
    return redirect(url)

@app.route("/list_users")
def list_users():
    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        return render_template("list.html", users=userdb.users)


@app.route("/user/<username>", methods=["POST", "GET"])
def user(username):
    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        new_user = username not in userdb
        if "REMOTE_USER" in request.headers:
            admin, admin_error_message = check_user_is_admin(request.headers["REMOTE_USER"])
        else:
            # No REMOTE_USER header, can't work
            message = "Can't work without REMOTE_USER header, contact an administrator"
            return render_template("message.html", success=False, message=message)
        admin_feature = False
        if admin and request.headers["REMOTE_USER"] != username:
            admin_feature = True

        if CONF["REQUIRE_REMOTE_USER"]:
            if not request.headers["REMOTE_USER"]:
                return render_template("message.html", message="Sorry, you must be logged with http basic auth to go here")
            if request.headers["REMOTE_USER"] != username or new_user:
                # User trying to change someone else password

                if not admin:
                    # User is not admin or admin group does exist. Ciao
                    return render_template("message.html", message=admin_error_message)

        if request.method == "GET":
            return render_template("user.html", username=username, new=new_user, admin_feature=admin_feature,
                                   password_pattern=CONF["PASSWORD_PATTERN"])
        else:
            # POST Request
            # If the generate random password is pressed
            if 'generaterandom' in request.form:
                new_password = generate_random_password()
                i = 0
                while not match(CONF["PASSWORD_PATTERN"], new_password):
                    new_password = generate_random_password()
                    i += 1
                    if i > 10:
                        # To prevent infinite loop
                        return render_template("message.html", message="Something wrong with password generation. Please try again.")
                if new_user:
                    userdb.add(username, new_password)
                    message = "User created with random password: %s" % new_password
                    return render_template("message.html", message=message, success=True)
                else:
                    userdb.change_password(username, new_password)
                    message = "User password changed with random password: %s" % new_password
                    return render_template("message.html", message=message, success=True)
            # If the validate button is pressed
            if request.form["new_password"] != request.form["repeat_password"]:
                return render_template("message.html", message="Password differ. Please hit back and try again")
            if not admin_feature and not check_password(userdb.new_users[username], request.form["old_password"]):
                return render_template("message.html", message="password does not match")
            if not match(CONF["PASSWORD_PATTERN"], request.form["new_password"]):
                return render_template("message.html", message="new password does not match requirements (%s" % CONF["PASSWORD_PATTERN_HELP"])
            # Ok, ready to change password or create user
            if new_user:
                userdb.add(username, request.form["new_password"])
                message = "User created"
            else:
                userdb.change_password(username, request.form["new_password"])
                message = "Password changed"
            if request.args.get("return_to"):
                return redirect(request.args.get("return_to"))
            else:
                return render_template("message.html", message=message, success=True)


@app.route("/user_groups/<username>", methods=["POST", "GET"])
def user_groups(username):
    if "REMOTE_USER" in request.headers:
        admin, message = check_user_is_admin(request.headers["REMOTE_USER"])
        if not admin:
            # User is not admin or admin group does exist. Ciao
            return render_template("message.html", message=message)
    else:
        # No REMOTE_USER header, can't work
        message="Can't work without REMOTE_USER header, contact an administrator"
        return render_template("message.html", success=False, message=message)

    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
            if request.method == "GET":
                groups = dict()
                for group in groupdb.groups:
                    if groupdb.is_user_in(username, group):
                        groups[group] = True
                    else:
                        groups[group] = False
                return render_template("groups.html", groups=groups)
            else:
                # POST Request
                checked_groups = [g.split("_", 1)[1] for g in request.form.keys() if g.startswith("group_")]
                for group in groupdb.groups:
                    if group in checked_groups:
                        if not groupdb.is_user_in(username, group):
                            groupdb.add_user(username, group)
                    else:
                        if groupdb.is_user_in(username, group):
                            groupdb.delete_user(username, group)
                return render_template("message.html", message="User groups changed", success=True)


@app.route("/batch_user_creation", methods=["POST", "GET"])
def batch_user_creation():
    if "REMOTE_USER" in request.headers:
        admin, message = check_user_is_admin(request.headers["REMOTE_USER"])
        if not admin:
            # User is not admin or admin group does exist. Ciao
            return render_template("message.html", message=message)
    else:
        # No REMOTE_USER header, can't work
        message="Can't work without REMOTE_USER header, contact an administrator"
        return render_template("message.html", success=False, message=message)

    with htpasswd.Basic(CONF["PWD_FILE"], mode="md5") as userdb:
        with htpasswd.Group(CONF["GROUP_FILE"]) as groupdb:
            if request.method == "GET":
                groups = []
                for group in groupdb.groups:
                    groups.append(group)
                return render_template("batch_user_creation.html", groups=groups)
            else:
                # POST Request
                users = request.form["users_login"].split("\r\n")
                checked_groups = [g.split("_", 1)[1] for g in request.form.keys() if g.startswith("group_")]
                result = []
                for username in users:
                    new_password = generate_random_password()
                    i = 0
                    while not match(CONF["PASSWORD_PATTERN"], new_password):
                        new_password = generate_random_password()
                        i += 1
                        if i > 10:
                            # To prevent infinite loop
                            return render_template("message.html",
                                                   message="Something wrong with password generation. Please try again.")
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
                return render_template("message.html", message=message, success=True, result=result)


def check_user_is_admin(user):
    """Ensure username is in admin group and that admin group exists
    @:return: tuple (result, message), result is True if user is admin, else False. message indicate reason if False"""
    with htpasswd.Group(CONF["GROUP_FILE"]) as groupsdb:
        if CONF["ADMIN_GROUP"] not in groupsdb:
            return (False, "Sorry admin group '%s' is not defined. You cannot change someone else password or create new user" % CONF["ADMIN_GROUP"])
        if not groupsdb.is_user_in(user, CONF["ADMIN_GROUP"]):
            return (False, "Sorry, you must belongs to group '%s' to change someone else password or create new users" % CONF["ADMIN_GROUP"])
        # Everything is fine
        return (True, "")


def check_password(encrypted_passwd, clear_passwd, mode="md5"):
    """check that password is correct against its hash
    TODO: propose to python-htpasswd to integrate this code in his lib"""
    salt = encrypted_passwd.split("$")[2]  # Extract salt from current encrypted password
    new_encrypted_passwd = subprocess.check_output(["openssl", "passwd", "-apr1", "-salt", salt, clear_passwd]).decode('utf-8')
    return encrypted_passwd == new_encrypted_passwd


def generate_random_password(length=8):
    """Generate a random password of the desired length
    @return a generated password of the desired length"""
    return "".join(random.sample(CONF["PASSWORD_GENERATION_CHARS"], length))


if __name__ == "__main__":
    app.debug = True
    app.run()
