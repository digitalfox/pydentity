#!/usr/bin/env python
# coding: utf-8
"""
Test suite for pydentity
@author: Sébastien Renard (sebastien.renard@digitalfox.org)
@license: AGPL v3 or newer (http://www.gnu.org/licenses/agpl-3.0.html)
"""

from pydentity import app, CONF

import htpasswd

import unittest
import os
from os.path import dirname, join

from pydentity import get_mail, generate_random_password


class BasicTestCase(unittest.TestCase):
    def setUp(self):
        self.passwd = join(dirname(__name__), "test_password")
        self.group = join(dirname(__name__), "test_group")
        open(self.passwd, "w").close()
        open(self.group, "w").close()
        with htpasswd.Basic(self.passwd, mode="md5") as userdb:
            userdb.add("user1", "user1")
            userdb.add("user2", "user2")
        with htpasswd.Group(self.group) as groupdb:
            groupdb.add_user("user1", "admin")
            groupdb.add_user("user1", "users")
            groupdb.add_user("user2", "users")
        app.config["TESTING"] = True
        CONF["PWD_FILE"] = self.passwd
        CONF["GROUP_FILE"] = self.group
        self.client = app.test_client()

    def tearDown(self):
        os.unlink(self.passwd)
        os.unlink(self.group)

    def test_ok_pages(self):
        for page in ("/user/user1", "/list_users"):
            r = self.client.get(CONF["URL_PREFIX"] + page)
            self.assertEqual(r.status_code, 200)

    def test_redirect_auth_user_to_its_page(self):
        r = self.client.get(CONF["URL_PREFIX"] + "/", environ_base={"REMOTE_USER": "user42"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/user/user42", r.location)
        r = self.client.get(CONF["URL_PREFIX"] + "/?return_to=/lala", environ_base={"REMOTE_USER": "user42"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/user/user42?return_to=/lala", r.location)

    def test_redirect_after_pwd_change(self):
        r = self.client.post(
            CONF["URL_PREFIX"] + "/user/user2?return_to=/lala",
            data={"old_password": "user2", "new_password": "New12345", "repeat_password": "New12345"},
            environ_base={"REMOTE_USER": "user2"},
        )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/lala", r.location)

    def test_change_my_passwd_as_admin(self):
        user = "user1"
        r = self.client.get(CONF["URL_PREFIX"] + "/user/%s" % user, environ_base={"REMOTE_USER": "%s" % user})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("Update of user %s" % user, data)
        self.assertNotIn("old_password", data)
        self.assertIn("generaterandom", data)

    def test_change_my_passwd_without_admin(self):
        user = "user2"
        r = self.client.get(CONF["URL_PREFIX"] + "/user/%s" % user, environ_base={"REMOTE_USER": "%s" % user})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("Update of user %s" % user, data)
        self.assertIn("old_password", data)
        self.assertNotIn("generaterandom", data)

    def test_change_my_passwd(self):
        for user in ("user1", "user2"):
            r = self.client.get(CONF["URL_PREFIX"] + "/user/%s" % user, environ_base={"REMOTE_USER": "%s" % user})
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertIn("Update of user %s" % user, data)
            r = self.client.post(
                CONF["URL_PREFIX"] + "/user/%s" % user,
                data={"old_password": "%s" % user, "new_password": "New12345", "repeat_password": "New12345"},
                environ_base={"REMOTE_USER": "%s" % user},
            )
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertIn("User password updated", data)
            r = self.client.post(
                CONF["URL_PREFIX"] + "/user/%s" % user,
                data={"old_password": "New12345", "new_password": "New12345678", "repeat_password": "New12345678"},
                environ_base={"REMOTE_USER": "%s" % user},
            )
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertIn("User password updated", data)
            r = self.client.post(
                CONF["URL_PREFIX"] + "/user/%s" % user,
                data={"old_password": "New12345678", "new_password": "new123456!", "repeat_password": "new123456!"},
                environ_base={"REMOTE_USER": "%s" % user},
            )
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertIn("User password updated", data)
            r = self.client.post(
                CONF["URL_PREFIX"] + "/user/%s" % user,
                data={"old_password": "new123456!", "new_password": "New!123456", "repeat_password": "New!123456"},
                environ_base={"REMOTE_USER": "%s" % user},
            )
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertIn("User password updated", data)
            r = self.client.post(
                CONF["URL_PREFIX"] + "/user/%s" % user,
                data={"old_password": "New!123456", "new_password": "new$!^-99", "repeat_password": "new$!^-99"},
                environ_base={"REMOTE_USER": "%s" % user},
            )
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertIn("User password updated", data)
            r = self.client.post(
                CONF["URL_PREFIX"] + "/user/%s" % user,
                data={"old_password": "new$!^-99", "new_password": "$#!^9NEw@&*-", "repeat_password": "$#!^9NEw@&*-"},
                environ_base={"REMOTE_USER": "%s" % user},
            )
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertIn("User password updated", data)

    def test_new_user(self):
        r = self.client.get(CONF["URL_PREFIX"] + "/user/xxx", environ_base={"REMOTE_USER": "xxx"})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertNotIn("Creation of user xxx", data)
        r = self.client.get(CONF["URL_PREFIX"] + "/user/xxx", environ_base={"REMOTE_USER": "user1"})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertNotIn("old_password", data)
        self.assertIn("Creation of user xxx", data)
        self.assertIn("generaterandom", data)
        r = self.client.post(
            CONF["URL_PREFIX"] + "/user/xxx",
            data={"new_password": "New12345", "repeat_password": "New12345"},
            environ_base={"REMOTE_USER": "user1"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("User created", data)
        with htpasswd.Basic(self.passwd, mode="md5") as userdb:
            self.assertIn("xxx", userdb)

    def test_change_someone_else_pwd_as_admin(self):
        r = self.client.get(CONF["URL_PREFIX"] + "/user/user2", environ_base={"REMOTE_USER": "user1"})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("Update of user user2", data)
        self.assertIn("Generate random password", data)
        self.assertNotIn("Old password", data)
        r = self.client.post(
            CONF["URL_PREFIX"] + "/user/user2",
            data={"new_password": "New12345", "repeat_password": "New12345"},
            environ_base={"REMOTE_USER": "user1"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("User password updated", data)

    def test_change_someone_else_pwd_as_nobody(self):
        r = self.client.get(CONF["URL_PREFIX"] + "/user/user1", environ_base={"REMOTE_USER": "user2"})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("Forbidden: only admin user allowed", data)
        r = self.client.post(
            CONF["URL_PREFIX"] + "/user/user1",
            data={"new_password": "New12345", "repeat_password": "New12345"},
            environ_base={"REMOTE_USER": "user2"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("Forbidden: only admin user allowed", data)

    def test_bad_passwd_change(self):
        for data, error_message in [
            (
                {"old_password": "XXXXX", "new_password": "New12345", "repeat_password": "New12345"},
                "Old password does not match",
            ),
            (
                {"old_password": "user2", "new_password": "New12345", "repeat_password": "New12345678"},
                "Passwords differ. Please try again",
            ),
            (
                {"old_password": "user2", "new_password": "new", "repeat_password": "new"},
                "New password does not match requirements",
            ),
        ]:
            r = self.client.post(CONF["URL_PREFIX"] + "/user/user2", data=data, environ_base={"REMOTE_USER": "user2"})
            self.assertEqual(r.status_code, 200)
            data = r.data.decode()
            self.assertNotIn("User password updated", data)
            self.assertIn(error_message, data)

    def test_add_group(self):
        r = self.client.get(CONF["URL_PREFIX"] + "/user/user1", environ_base={"REMOTE_USER": "user1"})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        for group in ("users", "admin"):
            self.assertIn("""name="group_%s" class="form-control" type="checkbox" checked""" % group, data)

        with htpasswd.Group(self.group) as groupdb:
            self.assertTrue(groupdb.is_user_in("user1", "users"))

        r = self.client.post(
            CONF["URL_PREFIX"] + "/user/user1",
            data={"new_password": "", "repeat_password": "", "group_admin": "on"},
            environ_base={"REMOTE_USER": "user1"},
        )

        with htpasswd.Group(self.group) as groupdb:
            self.assertEqual(r.status_code, 200)
            self.assertFalse(groupdb.is_user_in("user1", "users"))
            self.assertTrue(groupdb.is_user_in("user1", "admin"))

    def test_change_group_without_admin(self):
        r = self.client.post(
            CONF["URL_PREFIX"] + "/user/user2",
            data={"new_password": "", "repeat_password": "", "group_admin": "on"},
            environ_base={"REMOTE_USER": "user2"},
        )
        self.assertEqual(r.status_code, 200)
        with htpasswd.Group(self.group) as groupdb:
            self.assertFalse(groupdb.is_user_in("user1", "group_admin"))

    def test_batch_user_creation(self):
        r = self.client.get(CONF["URL_PREFIX"] + "/batch_user_creation", environ_base={"REMOTE_USER": "user1"})
        self.assertEqual(r.status_code, 200)

        r = self.client.post(
            CONF["URL_PREFIX"] + "/batch_user_creation",
            data={"users_login": "user13\r\nuser14", "group_users": "on"},
            environ_base={"REMOTE_USER": "user1"},
        )
        data = r.data.decode()
        self.assertEqual(r.status_code, 200)
        self.assertIn("Batch of user created with generated passwords", data)
        with htpasswd.Basic(self.passwd, mode="md5") as userdb:
            self.assertIn("user13", userdb)
            self.assertIn("user14", userdb)
        with htpasswd.Group(self.group) as groupdb:
            self.assertTrue(groupdb.is_user_in("user13", "users"))
            self.assertFalse(groupdb.is_user_in("user13", "admin"))
            self.assertTrue(groupdb.is_user_in("user14", "users"))
            self.assertFalse(groupdb.is_user_in("user14", "admin"))

    def test_batch_user_creation_with_mail(self):
        mail = get_mail()
        with mail.record_messages() as outbox:
            r = self.client.get(CONF["URL_PREFIX"] + "/batch_user_creation", headers={"REMOTE_USER": "user1"})
            self.assertEqual(r.status_code, 200)

            r = self.client.post(
                CONF["URL_PREFIX"] + "/batch_user_creation",
                data={
                    "users_login": "user18\r\nuser19",
                    "group_users": "on",
                    "send_mail": "on",
                    "mail_suffix": "@test.com",
                    "instance": "myclient",
                },
                environ_base={"REMOTE_USER": "user1"},
            )
            data = r.data.decode()
            self.assertEqual(r.status_code, 200)
            if CONF["ENABLE_MAIL_CAPABILITIES"]:
                self.assertIn(
                    "Batch of user created with generated passwords, a mail has been sent to all of them", data
                )
                self.assertEqual(len(outbox), 2)
                self.assertIn("Je vous prie de trouver les informations de connexion", outbox[0].body)
                self.assertEqual(["user18@test.com"], outbox[0].recipients)
                self.assertEqual(["user19@test.com"], outbox[1].recipients)

    def test_batch_user_creation_without_admin(self):
        r = self.client.get(CONF["URL_PREFIX"] + "/batch_user_creation", environ_base={"REMOTE_USER": "user2"})
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("Forbidden: only admin user allowed", data)

        r = self.client.post(
            CONF["URL_PREFIX"] + "/batch_user_creation",
            data={"group_admin": "on"},
            environ_base={"REMOTE_USER": "user2"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.data.decode()
        self.assertIn("Forbidden: only admin user allowed", data)

    def test_generate_password(self):
        password = generate_random_password()
        self.assertRegex(password, CONF["PASSWORD_PATTERN"])
        password = generate_random_password(11)
        self.assertRegex(password, CONF["PASSWORD_PATTERN"])
        self.assertEqual(len(password), 11)


if __name__ == "__main__":
    unittest.main()
