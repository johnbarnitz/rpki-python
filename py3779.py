#   IPAddrBlocks        ::= SEQUENCE OF IPAddressFamily

#   IPAddressFamily     ::= SEQUENCE {    -- AFI & optional SAFI --
#   addressFamily        OCTET STRING (SIZE (2..3)),
#   ipAddressChoice      IPAddressChoice }

#   IPAddressChoice     ::= CHOICE {
#   inherit              NULL, -- inherit from issuer --
#   addressesOrRanges    SEQUENCE OF IPAddressOrRange }

#   IPAddressOrRange    ::= CHOICE {
#   addressPrefix        IPAddress,
#   addressRange         IPAddressRange }

#   IPAddressRange      ::= SEQUENCE {
#   min                  IPAddress,
#  max                  IPAddress }

#   IPAddress           ::= BIT STRING
from asn1crypto.core import BitString, Choice, Integer, Null, OctetString, \
    Sequence, SequenceOf
from asn1crypto.x509 import AccessMethod, Certificate, Extension, \
    ExtensionId, PolicyIdentifier
import ipaddress

class IPAddress(BitString):
    def pad_or_truncate(self, some_list, target_len, padval=0):
        return list(some_list[:target_len]) + [padval]*(target_len - len(some_list))

    def toIPAddress(self,version):
        ipval = self.native
        if (version == 4):
            mask = len(ipval)
            ipbits = self.pad_or_truncate(ipval, 32)
            ipintval = int("".join(str(i) for i in ipbits),2)
            ipaddr = str(ipaddress.IPv4Address(ipintval))
        elif(version == 6):
            mask = len(ipval)
            ipbits = self.pad_or_truncate(ipval, 128)
            ipintval = int("".join(str(i) for i in ipbits),2)
            ipaddr = str(ipaddress.IPv6Address(ipintval))
        return "{}/{}".format(ipaddr,mask)
    def toMinIPAddress(self,version):
        ipval = self.native
        if (version == 4):
            ipbits = self.pad_or_truncate(ipval, 32)
            ipintval = int("".join(str(i) for i in ipbits),2)
            ipaddr = str(ipaddress.IPv4Address(ipintval))
        elif(version == 6):
            ipbits = self.pad_or_truncate(ipval, 128)
            ipintval = int("".join(str(i) for i in ipbits),2)
            ipaddr = str(ipaddress.IPv6Address(ipintval))
        return ipaddr

    def toMaxIPAddress(self,version):
        ipval = self.native
        if (version == 4):
            ipbits = self.pad_or_truncate(ipval, 32, padval=1)
            ipintval = int("".join(str(i) for i in ipbits),2)
            ipaddr = str(ipaddress.IPv4Address(ipintval))
        elif(version == 6):
            ipbits = self.pad_or_truncate(ipval, 128, padval=1)
            ipintval = int("".join(str(i) for i in ipbits),2)
            ipaddr = str(ipaddress.IPv6Address(ipintval))
        return ipaddr


class IPAddressRange(Sequence):
     _fields = [
        ('min', IPAddress),
        ('max', IPAddress)
    ]

class  IPAddressOrRange(Choice):
     _alternatives = [
        ('addressPrefix' ,   IPAddress),
        ('addressRange',   IPAddressRange )
     ]

class SequenceOfIPAddressOrRange(SequenceOf):
    _child_spec = IPAddressOrRange


class IPAddressChoice(Choice):
     _alternatives = [
        ( 'inherit',             Null),
        ( 'addressesOrRanges',     SequenceOfIPAddressOrRange )
    ]

class IPAddressFamily(Sequence):
    _fields = [
        ('addressFamily', OctetString),
        ('ipAddressChoice' ,IPAddressChoice)
    ]

class IPAddrBlocks(SequenceOf):
    _child_spec = IPAddressFamily

#

#
#   ASIdentifiers       ::= SEQUENCE {
#       asnum               [0] ASIdentifierChoice OPTIONAL,
#       rdi                 [1] ASIdentifierChoice OPTIONAL }

#   ASIdentifierChoice  ::= CHOICE {
#      inherit              NULL, -- inherit from issuer --
#      asIdsOrRanges        SEQUENCE OF ASIdOrRange }

#   ASIdOrRange         ::= CHOICE {
#       id                  ASId,
#       range               ASRange }

#   ASRange             ::= SEQUENCE {
#       min                 ASId,
#       max                 ASId }

#   ASId                ::= INTEGER

class ASId(Integer):
    pass

class ASRange(Sequence):
    _fields = [
        ('min', ASId),
        ('max', ASId)
    ]

class ASIdOrRange(Choice):
    _alternatives = [
        ( 'id', ASId),
        ( 'range', ASRange)
    ]

class SequenceOfASIdOrRange(SequenceOf):
    _child_spec = ASIdOrRange

class ASIdentifierChoice(Choice):
     _alternatives = [
        ( 'inherit',             Null),
        ( 'asIdsOrRanges',     SequenceOfASIdOrRange )
    ]

class ASIdentifiers(Sequence):
    _fields = [
        ('asnum', ASIdentifierChoice, {'explicit': 0, 'optional': True}),
        ('rdi', ASIdentifierChoice, {'explicit': 1, 'optional': True})
    ]

ExtensionId._map['1.3.6.1.5.5.7.1.7'] = 'id-pe-ipAddrBlocks'
ExtensionId._map['1.3.6.1.5.5.7.1.8'] = 'id-pe-autonomousSysIds'

Extension._oid_specs['id-pe-ipAddrBlocks'] = IPAddrBlocks
Extension._oid_specs['id-pe-autonomousSysIds'] = ASIdentifiers

PolicyIdentifier._map['1.3.6.1.5.5.7.14.2'] = 'id-cp-ipAddr-asNumber'

AccessMethod._map['1.3.6.1.5.5.7.48.10'] = 'id-ad-rpkiManifest'
AccessMethod._map['1.3.6.1.5.5.7.48.13'] = 'id-ad-rpkiNotify'
AccessMethod._map['1.3.6.1.5.5.7.48.11'] = 'id-ad-signedObject'
