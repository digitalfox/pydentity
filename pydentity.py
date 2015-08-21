# coding: utf-8
"""
Mini application to manage apache htpasswd file
@author: Sébastien Renard (sebastien.renard@digitalfox.org)
@license: AGPL v3 or newer (http://www.gnu.org/licenses/agpl-3.0.html)
"""

import subprocess
from os.path import dirname, join

from flask import Flask, render_template, request, redirect, url_for
import htpasswd


app = Flask(__name__)

# Configuration
PWD_FILE = join(dirname(__file__), "htpasswd")
GROUP_FILE = join(dirname(__file__), "htgroup")
# User may belong to this group to be able to change other user password. Need to require remote user (see below)
ADMIN_GROUP = "admin"
# Whether to require http basic auth upstream (for example with apache)
REQUIRE_REMOTE_USER = True


@app.route("/")
def home():
    if request.environ.get('REMOTE_USER'):
        return redirect(url_for("user", username=request.environ.get('REMOTE_USER')))
    else:
        return redirect(url_for("list_users"))


@app.route("/list_users")
def list_users():
    with htpasswd.Basic(PWD_FILE, mode="md5") as userdb:
        return render_template("list.html", users=userdb.users)


@app.route("/user/<username>", methods=['POST', 'GET'])
def user(username):
    with htpasswd.Basic(PWD_FILE, mode="md5") as userdb:
        if REQUIRE_REMOTE_USER:
            if not request.environ.get('REMOTE_USER'):
                return "Sorry, you must be logged with http basic auth to go here"
            if request.environ.get('REMOTE_USER') != username:
                # User trying to change someone else password
                with htpasswd.Group(GROUP_FILE) as groups:
                    if ADMIN_GROUP not in groups:
                        return "Sorry admin group '%s' is not defined. You cannot change someone else password" % ADMIN_GROUP
                    if not groups.is_user_in(request.environ.get('REMOTE_USER'), ADMIN_GROUP):
                        return "Sorry, you must belongs to group '%s' to change someone else password" % ADMIN_GROUP

        if request.method == "GET":
            if username in userdb:
                return render_template("user.html", username=username)
            else:
                return "Unknown user %s" % username
        else:
            if request.form["new_password"] != request.form["repeat_password"]:
                return "Password differ. Please hit back and try again"
            if not check_password(userdb.new_users[username], request.form["old_password"]):
                return "password does not match"
            else:
                # Ok, ready to change password
                userdb.change_password(username, request.form["new_password"])
                return "Password changed"


def check_password(encrypted_passwd, clear_passwd, mode="md5"):
    """check that password is correct against its hash
    TODO: propose to python-htpasswd to integrate this code in his lib"""
    salt = encrypted_passwd.split("$")[2]  # Extract salt from current encrypted password
    new_encrypted_passwd = subprocess.check_output(["openssl", "passwd", "-apr1", "-salt", salt, clear_passwd]).decode('utf-8')
    return encrypted_passwd == new_encrypted_passwd


if __name__ == "__main__":
    app.debug = True
    app.run()