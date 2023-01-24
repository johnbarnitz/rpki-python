from asn1crypto import crl
class RPKICrl(crl):
#    with open (filename) as f:
#        cert_list = crl.CertificateList.load(f.read())

    def getSerialNumbers(self):
        serial_numbers = []
        for revoked_cert in self['tbs_cert_list']['revoked_certificates']:
            serial_numbers.append(revoked_cert['user_certificate'].native)
        return serial_numbers
