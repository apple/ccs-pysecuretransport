##
# Copyright (c) 2010-2017 Apple Inc. All rights reserved.
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

from OpenSSL.crypto import load_keychain_identity
from osx._corefoundation import ffi, lib as cms
from osx.corefoundation import CFDataRef, CFObjectRef
import unittest


"""
Security framework CMS tests.
"""


class CMSTestCase(unittest.TestCase):
    """
    Tests for Security framework CMS cffi wrappers.
    """

    def test_cms_sign_verify_ok(self):
        """
        Use the simple encode.
        """

        # Sign some data
        sign = "Something to be signed"
        result = ffi.new("CFDataRef *")
        signer = load_keychain_identity("org.calendarserver.test")
        error = cms.CMSEncodeContent(
            signer.ref(),
            ffi.NULL,
            ffi.NULL,
            False,
            cms.kCMSAttrNone,
            sign,
            len(sign),
            result,
        )
        self.assertEqual(error, 0)
        result = CFDataRef(result[0])
        self.assertNotEqual(result.count(), 0)

        # Now verify the result
        decoder = ffi.new("CMSDecoderRef *")
        error = cms.CMSDecoderCreate(decoder)
        self.assertEqual(error, 0)
        decoder = CFObjectRef(decoder[0])

        error = cms.CMSDecoderUpdateMessage(decoder.ref(), result.toString(), result.count())
        self.assertEqual(error, 0)

        error = cms.CMSDecoderFinalizeMessage(decoder.ref())
        self.assertEqual(error, 0)

        number = ffi.new("size_t *")
        error = cms.CMSDecoderGetNumSigners(decoder.ref(), number)
        self.assertEqual(error, 0)
        self.assertEqual(number[0], 1)

        encrypted = ffi.new("Boolean *")
        error = cms.CMSDecoderIsContentEncrypted(decoder.ref(), encrypted)
        self.assertEqual(error, 0)
        self.assertEqual(encrypted[0], False)

        policy = cms.SecPolicyCreateBasicX509()
        policy = CFObjectRef(policy)
        status = ffi.new("CMSSignerStatus *")
        verify_result = ffi.new("OSStatus *")
        error = cms.CMSDecoderCopySignerStatus(
            decoder.ref(),
            0,
            policy.ref(),
            True,
            status,
            ffi.NULL,
            verify_result,
        )
        self.assertEqual(error, 0)
        self.assertEqual(status[0], cms.kCMSSignerValid)
        self.assertEqual(verify_result[0], 0)

        result = ffi.new("CFDataRef *")
        error = cms.CMSDecoderCopyContent(decoder.ref(), result)
        self.assertEqual(error, 0)
        result = CFDataRef(result[0])
        self.assertEqual(result.toString(), sign)

    def test_cms_sign_verify_badsig(self):
        """
        Use the simple encode.
        """

        # Sign some data
        sign = "Something to be signed"
        modified_sign = "Something to bb signed"
        result = ffi.new("CFDataRef *")
        signer = load_keychain_identity("org.calendarserver.test")
        error = cms.CMSEncodeContent(
            signer.ref(),
            ffi.NULL,
            ffi.NULL,
            False,
            cms.kCMSAttrNone,
            sign,
            len(sign),
            result,
        )
        self.assertEqual(error, 0)
        result = CFDataRef(result[0])
        self.assertNotEqual(result.count(), 0)

        # Hack the result to change one character
        result_count = result.count()
        result = result.toString().replace(sign, modified_sign)

        # Now verify the result
        decoder = ffi.new("CMSDecoderRef *")
        error = cms.CMSDecoderCreate(decoder)
        self.assertEqual(error, 0)
        decoder = CFObjectRef(decoder[0])

        error = cms.CMSDecoderUpdateMessage(decoder.ref(), result, result_count)
        self.assertEqual(error, 0)

        error = cms.CMSDecoderFinalizeMessage(decoder.ref())
        self.assertEqual(error, 0)

        number = ffi.new("size_t *")
        error = cms.CMSDecoderGetNumSigners(decoder.ref(), number)
        self.assertEqual(error, 0)
        self.assertEqual(number[0], 1)

        encrypted = ffi.new("Boolean *")
        error = cms.CMSDecoderIsContentEncrypted(decoder.ref(), encrypted)
        self.assertEqual(error, 0)
        self.assertEqual(encrypted[0], False)

        policy = cms.SecPolicyCreateBasicX509()
        policy = CFObjectRef(policy)
        status = ffi.new("CMSSignerStatus *")
        verify_result = ffi.new("OSStatus *")
        error = cms.CMSDecoderCopySignerStatus(
            decoder.ref(),
            0,
            policy.ref(),
            True,
            status,
            ffi.NULL,
            verify_result,
        )
        self.assertEqual(error, 0)
        self.assertEqual(status[0], cms.kCMSSignerInvalidSignature)
        self.assertEqual(verify_result[0], 0)

        result = ffi.new("CFDataRef *")
        error = cms.CMSDecoderCopyContent(decoder.ref(), result)
        self.assertEqual(error, 0)
        result = CFDataRef(result[0])
        self.assertEqual(result.toString(), modified_sign)
