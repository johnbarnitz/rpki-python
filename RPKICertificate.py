from asn1crypto import cms, util, algos, x509, core, pem
from py3779 import *


class RPKICertificate(Certificate):

    def _parse_sia(self, methodname):
        ret = None
        try:
            for i in self.subject_information_access_value:
                if i['access_method'].native == methodname:
                    ret = i['access_location'].native
        except TypeError:
            # probably shoud debug this
            # No sia found, return none
            pass

        return ret
    @property
    def ca_repository(self):
        return self._parse_sia('ca_repository')
    @property
    def rpki_manifest(self):
        return self._parse_sia('id-ad-rpkiManifest')
    @property
    def rpki_notify(self):
        return self._parse_sia('id-ad-rpkiNotify')
