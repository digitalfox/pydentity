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
        with htpasswd.Group(self.group) as group:
            group.add_user("user1", "admin")
            group.add_user("user1", "users")
            group.add_user("user2", "users")
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
        self.assertTrue("Change password for user user2" in r.data)
        r = self.client.post("/user/user2", data = {"old_password": "user2", "new_password": "new", "repeat_password":"new"}, environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Password changed", r.data)
        r = self.client.post("/user/user2", data = {"old_password": "new", "new_password": "new", "repeat_password":"new"}, environ_base = { "REMOTE_USER": "user2" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Password changed", r.data)


    def test_change_unknown_user(self):
        r = self.client.get("/user/xxx", environ_base = { "REMOTE_USER": "xxx" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Unknown user", r.data)


    def test_change_someone_else_pwd_as_admin(self):
        r = self.client.get("/user/user1", environ_base = { "REMOTE_USER": "user1" })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Change password for user user1", r.data)

if __name__ == "__main__":
    unittest.main()