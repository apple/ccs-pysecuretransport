##
# Copyright (c) 2010-2015 Apple Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

from OpenSSL import crypto
import os
import unittest


"""
crypto tests.
"""

class CryptoTestCase(unittest.TestCase):
    """
    Tests for L{crypto} module.
    """

    dataDir = os.path.join(os.path.dirname(__file__), "data")

    def test_load_certificate_pem(self):
        """
        Make sure L{crypto.load_certificate} can load a PEM file.
        """

        with open(os.path.join(self.dataDir, "server.pem")) as f:
            data = f.read()

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        self.assertTrue(isinstance(cert, crypto.X509))
        for item in cert.get_subject().get_components():
            if item[0] == "CN":
                self.assertEqual(item[1], "localhost")


    def test_load_privatekey_pem(self):
        """
        Make sure L{crypto.load_privatekey} can load a PEM file.
        """

        with open(os.path.join(self.dataDir, "server.pem")) as f:
            data = f.read()

        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, data)
        self.assertTrue(isinstance(pkey, crypto.PKey))
