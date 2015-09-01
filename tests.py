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


class BasicTestCase(unittest.TestCase):
    def setUp(self):
        self.passwd = join(dirname(__name__), "test_password")
        self.group = join(dirname(__name__), "test_group")
        open(self.passwd, "w")
        open(self.group, "w")
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
        for page in ("/user/user1", "/user/user1", "list_users"):
            r = self.client.get(page)
            self.assertEqual(r.status_code, 200)


    def test_default_redirect_to_list(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/list_users", r.location)


    def test_redirect_auth_user_to_its_page(self):
        r = self.client.get("/", environ_base = { "REMOTE_USER": "user42" })
        self.assertEqual(r.status_code, 302)
        self.assertIn("/user/user42", r.location)


    def test_change_my_passwd(self):
        r = self.client.get("/user/user2", environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Change password for user user2", r.data)
        r = self.client.post("/user/user2", data = {"old_password": "user2", "new_password": "new", "repeat_password":"new"}, environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Password changed", r.data)
        r = self.client.post("/user/user2", data = {"old_password": "new", "new_password": "new", "repeat_password":"new"}, environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Password changed", r.data)


    def test_new_user(self):
        r = self.client.get("/user/xxx", environ_base = { "REMOTE_USER": "xxx" })
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("old_password", r.data)
        self.assertIn("Creation of user xxx", r.data)
        r = self.client.post("/user/xxx", data = {"new_password": "new", "repeat_password":"new"}, environ_base = { "REMOTE_USER": "xxx" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("User created", r.data)
        with htpasswd.Basic(self.passwd, mode="md5") as userdb:
            self.assertIn("xxx", userdb)


    def test_change_someone_else_pwd_as_admin(self):
        r = self.client.get("/user/user2", environ_base = { "REMOTE_USER": "user1" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Change password for user user2", r.data)
        r = self.client.post("/user/user2", data = {"old_password": "user2", "new_password": "new", "repeat_password":"new"}, environ_base = { "REMOTE_USER": "user1" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Password changed", r.data)


    def test_change_someone_else_pwd_as_nobody(self):
        r = self.client.get("/user/user1", environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Sorry, you must belongs to group", r.data)
        r = self.client.post("/user/user1", data = {"old_password": "user1", "new_password": "new", "repeat_password":"new"}, environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Sorry, you must belongs to group", r.data)


    def test_bad_passwd_change(self):
        for data in [
            {"old_password": "XXXXX", "new_password": "new", "repeat_password":"new"},
            {"old_password": "user2", "new_password": "XXX", "repeat_password":"new"},
            {"old_password": "user2", "new_password": "new", "repeat_password":"XXX"},]:
            r = self.client.post("/user/user2", data = data, environ_base = { "REMOTE_USER": "user2" })
            self.assertEqual(r.status_code, 200)
            self.assertNotIn("Password changed", r.data)


    def test_add_group(self):
        r = self.client.get("/user_groups/user1", environ_base = { "REMOTE_USER": "user1" })
        self.assertEqual(r.status_code, 200)
        for group in ("users", "admin"):
            self.assertIn('''name="group_%s" type="checkbox" checked''' % group, r.data)

        with htpasswd.Group(self.group) as groupdb:
            self.assertTrue(groupdb.is_user_in("user1", "users"))

        r = self.client.post("/user_groups/user1", data = {"group_admin": "on"}, environ_base = { "REMOTE_USER": "user1"})

        with htpasswd.Group(self.group) as groupdb:
            self.assertEqual(r.status_code, 200)
            self.assertFalse(groupdb.is_user_in("user1", "users"))
            self.assertTrue(groupdb.is_user_in("user1", "admin"))


    def test_change_group_without_admin(self):
        r = self.client.get("/user_groups/user2", environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Sorry, you must belongs to group", r.data)

        r = self.client.post("/user_groups/user2", data = {"group_admin": "on"}, environ_base = { "REMOTE_USER": "user2"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Sorry, you must belongs to group", r.data)


if __name__ == "__main__":
    unittest.main()