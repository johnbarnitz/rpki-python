from asn1crypto import cms
from asn1crypto.core import OctetBitString
from bitarray import bitarray
import math
import rpki_scripts.rpki.roa
from py3779 import *
from rpki_scripts.rpki.manifest import *
from datetime import datetime
import pytz


class rpkiManifestOrROA(cms.ContentInfo):

    ADDRESS_FAMILY_IPV4 = b'\x00\x01'
    ADDRESS_FAMILY_IPV6 = b'\x00\x02'

    def _process_roa(self, roa):
        # Rewrite the IP addresses in the ipAddrBlocks to readable prefixes
        rval = {}
        rval['asn'] = roa['asID'].native
        rval['ipaddrs'] = []
        ip = None
        for ipx in roa['ipAddrBlocks']:

            addrfam = ipx['addressFamily'].native
            for ipy in ipx['addresses']:
                ipz = IPAddress(ipy['address'].native)
                if addrfam == self.ADDRESS_FAMILY_IPV4:
                    ip = ipz.toIPAddress(4)
                if addrfam == self.ADDRESS_FAMILY_IPV6:
                    ip = ipz.toIPAddress(6)
                rval['ipaddrs'].append([ip, ipy['maxLength'].native])
        return rval

    def _process_manifest(self, manifest):

        ret = {}
        ret['fileHashAlg'] = manifest['fileHashAlg'].native
        ret['nextUpdate'] = manifest['nextUpdate'].native
        ret['thisUpdate'] = manifest['thisUpdate'].native
        fharray = []

        for fileHash in manifest['fileList']:
            fh = {}
            fh['file'] = fileHash['file'].native
            fh['hash'] = fileHash['hash'].cast(OctetBitString).native.hex()
            fharray.append(fh)
    #    for fileHash in manifest['fileList']:
    #        fileHash['hash'] = bits_to_bytes(fileHash['hash']).hex()
        ret['files'] = fharray
        return ret

    def _process_certificate(self, certificate):
        # Rewrite ipAddressChoice
        ret = {}
        for ext in certificate['tbs_certificate']['extensions']:
            if ext['extn_id'].native == 'id-pe-ipAddrBlocks':

                for ipAddrFamily in ext['extn_value'].parse(IPAddrBlocks):

                    if ipAddrFamily['addressFamily'].native == self.ADDRESS_FAMILY_IPV4:
                        ret['addressFamily'] = 'IPv4'

                        if ipAddrFamily['ipAddressChoice'].chosen.native:
                            for k in ipAddrFamily['ipAddressChoice'].chosen:
                                print(k.chosen.toIPAddress(4))

                    elif ipAddrFamily['addressFamily'].native == self.ADDRESS_FAMILY_IPV6:
                        ret['addressFamily'] = 'IPv6'
                        if ipAddrFamily['ipAddressChoice'].chosen.native:
                            for k in ipAddrFamily['ipAddressChoice'].chosen:
                                print(k.chosen.toIPAddress(6))

    def _converttonetwork(self, ip):
        rpkiIPAddr = bitarray()
        if ip[0] == 0:
            mask = 0
        else:
            mask = int(math.log2(ip[0]))
        rpkiIPAddr.frombytes(ip[1:])
        while len(rpkiIPAddr) < 32:
            rpkiIPAddr.frombytes(b'\x00')

    #    print( ipaddress.ip_address(rpkiIPAddr.tobytes()))

        return str(ipaddress.ip_address(rpkiIPAddr.tobytes())) + '/' + str(mask + len(rpkiIPAddr[8:]))

    @property
    def enclosed_certificates(self):
        for c in self['content']['certificates']:
            certificate = c.parse()
            self._process_certificate(certificate)

    @property
    def manifestFiles(self):
        if self['content']['encap_content_info']['content_type'].native == 'rpkiManifest':
            fh = self._process_manifest(self['content']['encap_content_info']['content'].parse(RPKIManifest))
            return fh
        else:
            print("File is not a manifest")

    @property
    def roa(self):
        if self['content']['encap_content_info']['content_type'].native == 'routeOriginAuthz':
            roa = self._process_roa(self['content']['encap_content_info']['content'].parse(rpki_scripts.rpki.roa.RouteOriginAttestation))
            return roa
        else:
            print("File is not  a ROA")

    @property
    def iscurrent(self):
        if self['content']['encap_content_info']['content_type'].native == 'rpkiManifest':
            fh = self._process_manifest(self['content']['encap_content_info']['content'].parse(RPKIManifest))
            if fh['nextUpdate'] > datetime.now(pytz.timezone('US/Eastern')):
                return True
            else:
                return False
        else:
            return None


class RPKIMFT(rpkiManifestOrROA):
    pass


class RPKIROA(rpkiManifestOrROA):
    pass
