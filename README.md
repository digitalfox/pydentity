# What is it ?

Pydentity is a small web application that manage apache password file (htpasswd) with 
a simple browser.

Current features are:

- change your password by providing the previous one
- change other people password when you belongs the a specified admin group
- create new users
- handle authentication through http basic authentication (of course)

Caveats, limitations, so far:

- only md5 password hash are supported. Of course crypt password will never be. Blowfish could be supported one day
- only support http authentication. But frankly, if you want to manage htpasswd file you should have that don't you ?
- no way to reset password without previous one (like email or secret question for example)
- no group management

# How it works ?

Pydentity is developped on [python](http://www.python.org) and based on the micro framework [Flask](http://flask.pocoo.org/).
To handle htpasswd file format, it relies on python [htpasswd library](https://github.com/thesharp/htpasswd)
and [openssl](https://www.openssl.org/). No database is required.

Obviously, you need a WSGI compliant web server. It is tested with [Apache](http://httpd.apache.org/)
and [mod_wsgi](http://code.google.com/p/modwsgi/), but it should works with others (Gunicorn, Werkzeurg, uWSGI etc.)


# License

Pydentity is licensed under the [GNU Affero General Public Licence version 3 or newer](http://www.gnu.org/licenses/agpl-3.0.html)

# Installation

Prerequisites: 

- python 2.7
- WSGI compliant server (example: apache and mod_wsgi)
- openssl command line

Just drop the code where you want in a place that your webserver can read. You are advised to create a dedicated python
virtual environment to install python third party libs, but it's up to you ! the pydentity.wsgi file is setup with a
virtual env named "venv" at the root code level. If you don't use virtual env, comment this line, else, adapt it 
to you virtual env location. Install python requirements with this simple line:
 
 pip install -r requirement

Then setup your Webserver to target pydidentity.wsgi file. Here's a sample Apache + mod_wsgi configuration snippet
you could put in a virtual env definition:

    <Location />
        AuthName "pydentity"
        AuthType Basic
        AuthUserFile /var/www/htpasswd
        Require valid-user
    </Location>

    WSGIDaemonProcess pydentity threads=5 maximum-requests=10000 display-name=pydentity
    WSGIScriptAlias / /var/www/pydentity/pydentity.wsgi

    <Directory /var/www/pydentity/>
        WSGIProcessGroup pydentity
        WSGIApplicationGroup %{GLOBAL}
        Order deny,allow
        Allow from all
    </Directory>


# Configuration

Application configuration is very limited. Everything is in the prologue of pydentidy.py file in the CONF dict.
Here's the parameters you may want to tune:

    PWD_FILE: Full path to the htpasswd file to manage. Default to <pydentity dir>/htpasswd,
    GROUP_FILE: Full path the group file to manage. Default to <pydentity dir>/htgroup
    ADMIN_GROUP: Name of the admin group. Default to "admin". User need to belong to this group to be able to change other user password or create new users. REQUIRE_REMOTE_USER parameter is required
    REQUIRE_REMOTE_USER: Whether to require http basic auth upstream (for example with apache). Default to True. If False, everyone is able to change anyone password if the correct previous one is provided.
