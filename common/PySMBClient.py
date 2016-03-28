#!/usr/bin/env python3


class PySMBClient:

    def __init__(self, username="", password="", server=""):
        self._username = username
        self._password = password
        self._server = server
        self._command = ['smbclient']
