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
    "PASSWORD_PATTERN": "(?=.*\d)(?=.*[a-z])(?=.*[A-Z\!\@\#\$\%\^\&\*\-]).{8,}",
    # Clear text that explain to user the password requirements
    "PASSWORD_PATTERN_HELP" : "Lower case, numeric and upper case or special char. At least 8 char",
}


@app.route("/")
def home():
    if request.environ.get('REMOTE_USER'):
        url = url_for("user", username=request.environ.get('REMOTE_USER'))
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
        admin, admin_error_message = check_user_is_admin(request.environ.get('REMOTE_USER'))
        ask_old_password = True
        if admin and request.environ.get('REMOTE_USER') != username:
            ask_old_password = False
        if CONF["REQUIRE_REMOTE_USER"]:
            if not request.environ.get('REMOTE_USER'):
                return render_template("message.html", message="Sorry, you must be logged with http basic auth to go here")
            if request.environ.get('REMOTE_USER') != username or new_user:
                # User trying to change someone else password

                if not admin:
                    # User is not admin or admin group does exist. Ciao
                    return render_template("message.html", message=admin_error_message)

        if request.method == "GET":
            return render_template("user.html", username=username, new=new_user, ask_old_password=ask_old_password,
                                   password_pattern=CONF["PASSWORD_PATTERN"])
        else:
            # POST Request
            if request.form["new_password"] != request.form["repeat_password"]:
                return render_template("message.html", message="Password differ. Please hit back and try again")
            if ask_old_password and not check_password(userdb.new_users[username], request.form["old_password"]):
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

    admin, message = check_user_is_admin(request.environ.get('REMOTE_USER'))
    if not admin:
        # User is not admin or admin group does exist. Ciao
        return render_template("message.html", message=message)

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
                print request.form.items()
                checked_groups = [g.split("_", 1)[1] for g in request.form.keys() if g.startswith("group_")]
                print checked_groups
                for group in groupdb.groups:
                    if group in checked_groups:
                        if not groupdb.is_user_in(username, group):
                            print "add user to group %s" % group
                            groupdb.add_user(username, group)
                    else:
                        if groupdb.is_user_in(username, group):
                            print "remove user from group %s" % group
                            groupdb.delete_user(username, group)
                return render_template("message.html", message="User groups changed", success=True)



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


if __name__ == "__main__":
    app.debug = True
    app.run()
