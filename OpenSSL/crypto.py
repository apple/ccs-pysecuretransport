##
# Copyright (c) 2015 Apple Inc. All rights reserved.
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

"""
An API compatible replace for pyOpenSSL's OpenSSL.crypto module that uses Security.frameowork.
"""

from osx._corefoundation import ffi, lib as security
from osx.corefoundation import CFDictionaryRef, CFStringRef, CFArrayRef, \
    CFBooleanRef, CFObjectRef, CFErrorRef

userIDOID = "0.9.2342.19200300.100.1.1"

OID2STR = {
    str(CFStringRef.fromRef(security.kSecOIDCommonName)): "CN",
    str(CFStringRef.fromRef(security.kSecOIDCountryName)): "C",
    str(CFStringRef.fromRef(security.kSecOIDEmailAddress)): "emailAddress",
    str(CFStringRef.fromRef(security.kSecOIDLocalityName)): "L",
    str(CFStringRef.fromRef(security.kSecOIDOrganizationName)): "O",
    str(CFStringRef.fromRef(security.kSecOIDOrganizationalUnitName)): "OU",
    str(CFStringRef.fromRef(security.kSecOIDStateProvinceName)): "ST",
    userIDOID: "UID",
}

FILETYPE_PEM = 1
FILETYPE_ASN1 = 2
FILETYPE_DEFAULT = 3

TYPE_RSA = 6
TYPE_DSA = 116

class Error(Exception):
    """
    An error occurred in an `OpenSSL.crypto` API.
    """
    pass



class X509Name(object):
    """
    Equivalent of an pyOpenSSL OpenSSL.crypto.X509Name object.
    """
    def __init__(self, name, components=None):
        self.name = name
        self.components = components


    def get_components(self):
        return self.components.items()



class X509(object):
    """
    Equivalent of an pyOpenSSL OpenSSL.crypto.X509Name object, with many methods unimplemented.
    """

    def __init__(self, certificate=None):
        self.certificate = certificate


    def set_version(self, version):
        raise NotImplementedError


    def get_version(self):
        raise NotImplementedError


    def get_pubkey(self):
        raise NotImplementedError


    def set_pubkey(self, pkey):
        raise NotImplementedError


    def sign(self, pkey, digest):
        raise NotImplementedError


    def get_signature_algorithm(self):
        raise NotImplementedError


    def digest(self, digest_name):
        raise NotImplementedError


    def subject_name_hash(self):
        raise NotImplementedError


    def set_serial_number(self, serial):
        raise NotImplementedError


    def get_serial_number(self):
        raise NotImplementedError


    def gmtime_adj_notAfter(self, amount):
        raise NotImplementedError


    def gmtime_adj_notBefore(self, amount):
        raise NotImplementedError


    def has_expired(self):
        raise NotImplementedError


    def get_notBefore(self):
        raise NotImplementedError


    def set_notBefore(self, when):
        raise NotImplementedError


    def get_notAfter(self):
        raise NotImplementedError


    def set_notAfter(self, when):
        raise NotImplementedError


    def _get_name(self, which):
        raise NotImplementedError


    def _set_name(self, which, name):
        raise NotImplementedError


    def get_issuer(self):
        raise NotImplementedError


    def set_issuer(self, issuer):
        raise NotImplementedError


    def get_subject(self):
        """
        Use Security.framework to extract the componentized SubjectName field and map OID
        values to strings and store in an L{X509Name} object.
        """
        keys = CFArrayRef.fromList([CFStringRef.fromRef(security.kSecOIDX509V1SubjectName)])
        error = ffi.new("CFErrorRef *")
        values = security.SecCertificateCopyValues(self.certificate.ref(), keys.ref(), error)
        if values == ffi.NULL:
            error = CFErrorRef(error[0])
            raise Error("Unable to get certificate subject")
        values = CFDictionaryRef(values).toDict()
        value = values[str(CFStringRef.fromRef(security.kSecOIDX509V1SubjectName))]

        components = {}
        if value[str(CFStringRef.fromRef(security.kSecPropertyKeyType))] == str(CFStringRef.fromRef(security.kSecPropertyTypeSection)):
            for item in value[str(CFStringRef.fromRef(security.kSecPropertyKeyValue))]:
                if item[str(CFStringRef.fromRef(security.kSecPropertyKeyType))] == str(CFStringRef.fromRef(security.kSecPropertyTypeString)):
                    v = item[str(CFStringRef.fromRef(security.kSecPropertyKeyValue))]
                    k = OID2STR.get(item[str(CFStringRef.fromRef(security.kSecPropertyKeyLabel))], "Unknown")
                    components[k] = v


        return X509Name("Subject Name", components)


    def set_subject(self, subject):
        raise NotImplementedError


    def get_extension_count(self):
        raise NotImplementedError


    def add_extensions(self, extensions):
        raise NotImplementedError


    def get_extension(self, index):
        raise NotImplementedError



def load_certificate(certtype, buffer):
    """
    Load a certificate with the supplied identity string.

    @param certtype: ignored
    @type certtype: -
    @param buffer: name of the KeyChain item to lookup
    @type buffer: L{str}

    @return: the certificate
    @rtype: L{X509}
    """

    # First try to get the identity from the KeyChain
    name = CFStringRef.fromString(buffer)
    certificate = security.SecCertificateCopyPreferred(name.ref(), ffi.NULL)
    if certificate == ffi.NULL:
        try:
            identity = _getIdentityCertificate(buffer)
        except Error:
            raise Error("Certificate for preferred name '{}' was not found".format(buffer))
        certificate = ffi.new("SecCertificateRef *")
        err = security.SecIdentityCopyCertificate(identity.ref(), certificate)
        if err != 0:
            raise Error("Certificate for preferred name '{}' was not found".format(buffer))
        certificate = certificate[0]
    certificate = CFObjectRef(certificate)

    return X509(certificate)



def _getIdentityCertificate(subject):
    """
    Retrieve a SecIdentityRef from the KeyChain with a subject that exactly matches the passed in value.

    @param subject: subject value to match
    @type subject: L{str}

    @return: matched SecIdentityRef item or L{None}
    @rtpe: L{CFObjectRef}
    """
    match = CFDictionaryRef.fromDict({
        CFStringRef.fromRef(security.kSecClass): CFStringRef.fromRef(security.kSecClassIdentity),
        CFStringRef.fromRef(security.kSecReturnRef): CFBooleanRef.fromBool(True),
        CFStringRef.fromRef(security.kSecReturnAttributes): CFBooleanRef.fromBool(True),
        CFStringRef.fromRef(security.kSecMatchLimit): CFStringRef.fromRef(security.kSecMatchLimitAll),
    })
    result = ffi.new("CFTypeRef *")
    err = security.SecItemCopyMatching(
        match.ref(),
        result
    )
    if err != 0:
        return None

    result = CFArrayRef(result[0])
    for item in result.toList():
        if item[str(CFStringRef.fromRef(security.kSecAttrLabel))] == subject:
            identity = item[str(CFStringRef.fromRef(security.kSecValueRef))]
            break
    else:
        raise Error("Certificate with id '{}' was not found in the KeyChain".format(subject))

    return identity


if __name__ == '__main__':
    x = load_certificate("", "APSP:d6e49079-75ba-4380-a2cd-a66191469145")
    print(x.get_subject().get_components())
