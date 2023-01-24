#!/usr/bin/env python

import tal
import urllib.request
import urllib.parse
import urllib.error
import sysrsync
from RPKICertificate import *
import base64
from time import sleep
import os
from RPKIManifestOrROA import rpkiManifestOrROA
from asn1crypto import crl
import hashlib
from rpkicertvalidator.rpkicertvalidator import CertificateValidator, ValidationContext, errors
import json
from lxml import etree
from rrdp_tools.rrdp import validate
from collections import defaultdict
import logging
from pathlib import Path

from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import X509Store, X509StoreContext, FILETYPE_PEM


log = logging.getLogger(__name__)

logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"))


class SerialNumberException(Exception):
    pass


class InfiniteLoopExeception(Exception):
    pass


class InvalidTalFileException(Exception):
    pass


class RRDPCollector:
    def __init__(self, talfile, rpkifiledir, taldir):
        self.rrdplist = []
        self.rsynclist = defaultdict(dict)
        self.certificatestack = []
        self.certificateids = {}
        self.intermediatecertificates = {}
        self.intermediatecertificates_serial = {}
        self.validROA = {}
        self.use_openssl = True
        https_uri = None
        rsync_uri = None
        self.retry_count = 3
        self.delay = 5
        self.tal = talfile
        self.rpkifiledir = rpkifiledir
        self.rrdpfiledir = rpkifiledir + "/rrdp"
        self.serial_file_path = os.path.normpath(os.path.join(rpkifiledir + "/rrdp", "./serialno"))
        self.numroas = 0
        self.numfailedroas = 0
        self.numinvalidroas = 0
        self.numcertificates = 0
        self.numfailedcertificates = 0
        self.numinvalidcertificates = 0
        self.nummanifests = 0
        self.numfailedmanifests = 0
        self.numstalemanifests = 0
        self.numcrls = 0
        self.numgbrs = 0
        if not os.path.exists(self.serial_file_path):
            with open(self.serial_file_path, 'w') as r:
                r.write(json.dumps({}))
            self.serialdata = {}
        else:
            with open(self.serial_file_path, 'r') as r:
                self.serialdata = json.load(r)

        log.info(f"Starting Tal {talfile}")
        t = tal.tal(value=f"{taldir}/{talfile}")

        for uri in t.uri:
            if uri.scheme == 'https':
                https_uri = urllib.parse.urlunparse(uri)
            elif uri.scheme == 'rsync':
                rsync_uri = urllib.parse.urlunparse(uri)
        r = None
        if https_uri:
            request_site = urllib.request.Request(https_uri, headers={"User-Agent": "Mozilla/5.0"})
            try:
                with urllib.request.urlopen(request_site, timeout=10) as c:
                    cert = c.read()
            except urllib.error.HTTPError as e:
                # do something
                log.error('Error code: ', e.code, 'from', https_uri)
            except urllib.error.URLError as e:
                # do something
                log.error('Reason: ', e.reason, 'from', https_uri)
            r = RPKICertificate.load(cert)

        if rsync_uri and not r:
            log.info(f"Attempting to rsync from {rsync_uri}")
            try:
                sysrsync.run(source=rsync_uri, destination=rpkifiledir, sync_source_contents=False,
                         options=['--timeout=60', '-a'])
            except Exception as err:
                log.error(f"Could not rsync from {rsync_uri}, Exception {err} ")
                raise err;

            mfurl = urllib.parse.urlparse(rsync_uri)
            talcert = os.path.join(rpkifiledir, os.path.basename(mfurl.path))
            with open(talcert, 'rb') as c:
                cert = c.read()
            r = RPKICertificate.load(cert)
        if not r:
            log.error(f"Invalid tal file {talfile}")
            raise InvalidTalFileException

        if t.key == r.public_key.dump():
            log.info("Validation of root Key success")
            self.root = r
        else:
            log.info("Root key Failed, TAL is invalid or path is not trusted")
            raise InvalidTalFileException
        self.certificatestack.append(r)

    def start(self):
        log.debug(f"Starting  Validation {len(self.certificatestack)}")
        while len(self.certificatestack) > 0:
            x = self.certificatestack.pop()
            try:
                self.extractcertificate(x)
            except Exception as err:
                log.error(f"Exception {err}")

    def process_rsync(self, manifest, repository, repopath=None):
        mfpath = None
        if not repopath:
            repopath = self.get_rsync_repository(repository)
            mfpath = self.get_manifest(manifest)
        try:
            log.debug(f"Rsyncing to Repo  {repopath} Manifest {mfpath}")
            Path(repopath).mkdir(parents=True, exist_ok=True)
            sysrsync.run(source=repository, destination=repopath, sync_source_contents=False,
                         options=['--timeout=60', '-a'])
            sysrsync.run(source=manifest, destination=mfpath, sync_source_contents=False,
                         options=['--timeout=60', '-a'])
        except Exception as err:
            log.error(f"Could not rsync from {repository} {manifest}, Exception {err} ")
            #       return -1
            raise err

    def extractcertificate(self, r):
        do_rsync = False
        if r.rpki_notify:
            if r.rpki_notify not in self.rrdplist or not os.path.exists(self.get_manifest(r.rpki_manifest)):
                try:
                    self.process_rrdp(r.rpki_notify)

                except Exception as err:
                    log.error(f"Exception {err}")
                    do_rsync = True
                self.rrdplist.append(r.rpki_notify)
                self.rsynclist[r.rpki_notify][r.rpki_manifest] = r.ca_repository
            else:
                log.debug(f"Already Processed {r.rpki_notify}")
        else:
            do_rsync = True
            self.rsynclist[None][r.rpki_manifest] = r.ca_repository

        if do_rsync:
            log.info(f"Attempting to rsync from  {r.ca_repository} {r.rpki_manifest} ")
            manifestfile = self.get_manifest(r.rpki_manifest, True)
            repopath = self.get_repository(r.ca_repository, True)
            self.process_rsync(r.rpki_manifest, r.ca_repository)
        else:
            manifestfile = self.get_manifest(r.rpki_manifest, False)
            repopath = self.get_repository(r.ca_repository, False)
        log.info(f"Reading Manifest {manifestfile}")
        self.nummanifests += 1
        try:
            with open(manifestfile, "rb") as f:
                info = rpkiManifestOrROA.load(f.read())
        except Exception as e:
            log.error(f"File Exception {e} trying to open {manifestfile}")
            self.numfailedmanifests += 1
            raise e
        end_entity_cert = None
        for c in info['content']['certificates']:
            end_entity_cert = c.parse()

        if not end_entity_cert:
            log.error(f"Manifest {manifestfile} does not contain certificate")
            return []
        intermediates = self.getintermediates(end_entity_cert)
        context = self.getvalidationcontext(None)
        if self.use_openssl:
            try:
                self.openssl_validation(intermediates, end_entity_cert)
            except Exception as e:
                log.error(f"Error {e} Validating Manifest")
        else:
            try:
                validator = CertificateValidator(end_entity_cert, intermediates, validation_context=context)
                vpath = validator.validate_usage({'digital_signature'}, extended_optional=True)
            except errors.PathValidationError as e:
                log.error(f"Error Validating Manifest {e}")
                raise e

        manifestlist = info.manifestFiles
        revoke = None
        # ROA/Certs processed after crl
        certificatelist = []
        roalist = []
        for m in manifestlist['files']:
            containedfile = os.path.join(repopath, m['file'])
            hasher = None
            if manifestlist['fileHashAlg'] == 'sha256':
                hasher = hashlib.sha256()
            try:
                with open(containedfile, 'rb') as cfile:
                    buf = cfile.read()
                    hasher.update(buf)
            except IOError as e:
                log.error(f"File Not Found {containedfile} {e}")
                continue
            if hasher.hexdigest() == m['hash']:
                log.info(f"file { containedfile} has valid hash")
            else:
                log.error(f"file {containedfile} has hash mismatch {hasher.hexdigest()} {m['hash']}")
                continue

            file, ext = os.path.splitext(containedfile)
            ext = ext.lower()

            if ext == ".crl":
                revoke = self.process_revocation(containedfile)
                self.numcrls += 1
            if ext == ".cer":
                certificatelist.append(containedfile)
                self.numcertificates = 0
            if ext == ".roa":
                roalist.append(containedfile)
                self.numroas += 1
        for containedfile in certificatelist:
            try:
                with open(containedfile, "rb") as f:
                    cert = f.read()
                log.info(f"File is {containedfile}")
                r = RPKICertificate.load(cert)
            except Exception as e:
                log.error(f"Failed loading certificate {containedfile} {e}")
                self.numfailedcertificates += 1
            serialexists = r.serial_number in self.intermediatecertificates_serial
            if (not serialexists or
                    serialexists and
                    self.intermediatecertificates_serial[r.serial_number] != r.subject.human_friendly):
                self.certificatestack.append(r)
                self.intermediatecertificates[r.subject.human_friendly] = r
                self.intermediatecertificates_serial[r.serial_number] = r.subject.human_friendly
        for containedfile in roalist:
            try:
                rv = self.validate_roa(containedfile,  revoke)
            except Exception as e:
                log.error(f"Error ROA {e}")

                continue
            self.validROA.update(rv)

        return 0

    def process_rrdp(self, rrdp_uri):
        log.info(f"RRDP_uri, path {rrdp_uri} ")
        if rrdp_uri in self.serialdata:
            serial = self.serialdata[rrdp_uri]
            try:
                serial = self.get_deltas(rrdp_uri, serial)
            except SerialNumberException:
                log.error("Error with serial number, getting full snapshot")
                serial = self.get_snapshot(rrdp_uri)
            except Exception as e:
                raise e
        else:
            try:
                serial = self.get_snapshot(rrdp_uri)
            except Exception as e:
                raise e
        self.serialdata[rrdp_uri] = serial

    def get_deltas(self, rrdp_uri, serial):

        log.info(f"Getting Deltaas URL {rrdp_uri} serial {serial} ")
        request_site = urllib.request.Request(rrdp_uri, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(request_site, timeout=10) as c:
                rrdp_str = c.read()
        except Exception as e:
            log.error(f"Exception {e} getting XML from {rrdp_uri}, XML data is {rrdp_str} ")
            raise e
        doc = etree.fromstring(rrdp_str)
        log.info(f"Got URL {rrdp_uri}")
        try:
            validate(doc)
        except Exception as e:
            log.info(f"Loading {rrdp_str} XML Error {e}")
            raise e

        log.info(f"Document Validated")

        notification = doc.xpath("//*[local-name() = 'notification']")
        currentserial = int(notification[0].get('serial'))
        log.info(f"RRDP Last serial {serial}, server serial {currentserial}")
        if serial > currentserial:
            log.warning(f"RRDP Last serial {serial} is higher than current serial {currentserial}")
            raise SerialNumberException

        elems = doc.xpath("//*[local-name() = 'delta']")
        delta = []
        for elem in elems:
            cmpserial = int(elem.attrib['serial'])
            if cmpserial > serial:
                delta.append([cmpserial, elem.attrib['uri']])
        log.debug("Looking for deltas")
        if delta:
            mindelta = min(x[0] for x in delta)
            if mindelta > serial + 1:
                # the state is too far behind
                log.warning(f"RRDP Delta is too far behind, last serial {serial} server minimum serial {mindelta}")
                raise SerialNumberException
        for d in sorted(delta, key=lambda x: x[0]):
            log.info(f"RRDP delta serial {d[0]} URL {d[1]}")
            request_site = urllib.request.Request(d[1], headers={"User-Agent": "Mozilla/5.0"})
            try:
                with urllib.request.urlopen(request_site, timeout=10) as c:
                    rrdp_str = c.read()
            except Exception as e:
                log.error(f"Exception {e} getting {d[1]}")
                continue
            doc = etree.fromstring(rrdp_str)
            try:
                validate(doc)
            except Exception as e:
                log.info(rrdp_str)
                log.info(f"Delta XML Error {e}")

            # Document is valid
            log.info("Delta Document is Valid")
            elems = doc.xpath("//*[local-name() = 'publish]")
            for elem in elems:
                uri = elem.attrib['uri']
                # Take the path component of the URI and build the directory
                tokens = urllib.parse.urlparse(uri)
                file_path = os.path.normpath(os.path.join(self.rrdpfiledir, f"./{tokens.path}"))
                target_dir = os.path.dirname(file_path)
                if not os.path.isdir(target_dir):
                    os.makedirs(target_dir)
                log.info(f"RRDP Writing file {file_path}")
                with open(file_path, 'wb') as f:
                    f.write(base64.b64decode(elem.text))
            elems = doc.xpath("//*[local-name() = 'withdraw']")
            for elem in elems:
                uri = elem.attrib['uri']
                # Take the path component of the URI and build the directory for it
                tokens = urllib.parse.urlparse(uri)
                file_path = os.path.normpath(os.path.join(self.rrdpfiledir, f"./{tokens.path}"))
                try:
                    log.info(f"RRDP Removing file {file_path}")
                    os.remove(file_path)
                except FileNotFoundError:
                    log.info(f"File does not exist and could not be removed {file_path}")

        if delta:
            serial = max(x[0] for x in delta)
            log.info(f"RRDP New serial for {rrdp_uri} is {serial}")
        else:
            log.info("RRDP No updates found")
        return serial

    def get_snapshot(self, rrdp_uri):
        output_path = self.rrdpfiledir
        log.debug(f"Get Snapshot {rrdp_uri} {output_path}")
        request_site = urllib.request.Request(rrdp_uri, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(request_site, timeout=10) as c:
                rrdp_str = c.read()
        except Exception as e:
            log.error(f" Exception {e} retrieving from {rrdp_uri}")
            raise e
        doc = etree.fromstring(rrdp_str)
        try:
            validate(doc)
        except Exception as e:
            log.info(rrdp_str)
            log.info(f"XML Error {e}")
            raise e

        for child in doc:
            if child == "snapshot":
                etree.dump(child)
        snapshot = doc.xpath("//*[local-name() = 'snapshot']")

        uri = snapshot[0].attrib['uri']
        serial = doc.get('serial')
        log.info(f"Got {uri} to {output_path} serial is {serial}")
        self.reconstruct_repo(uri)
        return int(serial)

    def reconstruct_repo(self, rrdp_uri):
        log.debug(f"Getting URL, {rrdp_uri}")
        rrdp_str = self.retrieve_url(rrdp_uri)
        doc = etree.fromstring(rrdp_str)
        validate(doc)

        elems = doc.xpath("//*[local-name() = 'publish']")
        for elem in elems:
            uri = elem.attrib['uri']
            file_path = self.build_directory(uri)
            with open(file_path, 'wb') as f:
                f.write(base64.b64decode(elem.text))

    def retrieve_url(self, url):
        request_site = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        for _ in range(self.retry_count):
            try:
                with urllib.request.urlopen(request_site, timeout=10) as c:
                    url_str = c.read()
                    break
            except:
                pass
            log.info("waiting for retry")
            sleep(self.delay)
        else:
            log.error("Exception in read")
        return url_str

    def build_directory(self, uri):
        tokens = urllib.parse.urlparse(uri)
        file_path = os.path.normpath(os.path.join(self.rrdpfiledir, f"./{tokens.path}"))
        target_dir = os.path.dirname(file_path)
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)
        return file_path

    def getintermediates(self, cer):
        intermediates = []
        tmpcer = cer
        x = 0
        if self.root:
            while tmpcer.issuer != self.root.subject:
                intermediates.append(tmpcer)
                tmpcer = self.intermediatecertificates[tmpcer.issuer.human_friendly]
                x += 1
                if x > 100:
                    log.fatal("Loop detection")
                    raise InfiniteLoopExeception
            if x > 0:
                intermediates.append(tmpcer)
        return intermediates

    def read_certificate(self, filename):
        with open(filename, "rb") as f:
            cert = f.read()
        log.info(f"File is {filename}")
        r = RPKICertificate.load(cert)
        self.certificateids[r.subject.human_friendly] = filename
        self.intermediatecertificates[r.subject.human_friendly] = r
        rvlist = self.extractcertificate(r)
        return rvlist

    def getvalidationcontext(self, crlfile):
        # Collect all the revocations and the root certificate, and create a Validataion Context

        crls = []
        if crlfile:
            with open(crlfile, 'rb') as f:
                crls.append(f.read())

        return ValidationContext(crls=crls, trust_roots=[self.root.dump()])

    def validate_roa(self, roa, revoke):
        try:
            with open(roa, "rb") as f:
                info = rpkiManifestOrROA.load(f.read())
        except Exception as e:
            log.error(f"Error opening or parsing {roa} {e}")
            self.numfailedroas += 1
            return None
        end_entity_cert = None
        #TODO Can there be multiple certificates?
        for c in info['content']['certificates']:
            end_entity_cert = c.parse()
        if not end_entity_cert:
            log.error(f"ROA {roa} does not contain certificates")
            self.numfailedroas += 1
            return None
        log.debug("Get intermediates")
        intermediates = self.getintermediates(end_entity_cert)
        if self.use_openssl:
            try:
                self.openssl_validation(intermediates, end_entity_cert)
            except Exception as e:
                log.error(f"Error {e} Validating ROA")
        else:
            # Use the python validation library, however this is very slow
            context = self.getvalidationcontext(revoke)

            try:
                log.debug("Create Validator")
                validator = CertificateValidator(end_entity_cert, intermediates, validation_context=context)
                log.debug("Validate Usage")
                vpath = validator.validate_usage({'digital_signature'}, extended_optional=True)
                log.debug("Validate Subnets")
                validator.validate_ip_subnets()
            except errors.PathValidationError as e:
                # The certificate could not be validated)
                log.error(f"Error validating {roa} Certificate validation error {e}")
                self.numinvalidroas += 1
                raise e
        log.info("ROA Certificate Valid")
        log.info("-------")
        log.info(info.roa)
        log.info("-------")

        return {end_entity_cert.serial_number: [info.roa, end_entity_cert.not_valid_after.timestamp()]}

    def openssl_validation(self, intermediates, roa_cert_obj):
        store = X509Store()
        root_pem = self.cert_to_pem(self.root)
        root_cert = load_certificate(FILETYPE_PEM, root_pem)
        store.add_cert(root_cert)
        for i in intermediates:
            intermediate_cert_pem = self.cert_to_pem(i)
            intermediate_cert = load_certificate(FILETYPE_PEM, intermediate_cert_pem)
            store.add_cert(intermediate_cert)
        roa_cert_pem = self.cert_to_pem(roa_cert_obj)
        roa_cert = load_certificate(FILETYPE_PEM, roa_cert_pem)
        store_ctx = X509StoreContext(store, roa_cert)
        store_ctx.verify_certificate()
        # if above didn't throw an exception, success
        log.debug("Certifcate Validated Successfully")

    def cert_to_pem(self, cert):
        der_bytes = cert.dump()
        pem_bytes = pem.armor('CERTIFICATE', der_bytes)
        return pem_bytes

    def process_revocation(self, containedfile):
        with open(containedfile, 'rb') as f:
            cert_list = crl.CertificateList.load(f.read())

        serial_numbers = []
        for revoked_cert in cert_list['tbs_cert_list']['revoked_certificates']:
            serial_numbers.append(revoked_cert['user_certificate'].native)
        for s in serial_numbers:
            if s in self.intermediatecertificates_serial:
                del self.intermediatecertificates[self.intermediatecertificates_serial[s]]
                del self.intermediatecertificates_serial[s]
            if s in self.validROA:
                del self.validROA[s]
        return containedfile

    def rrdppoller(self):

        for i in self.rrdplist:
            try:
                self.process_rrdp(i)
            except Exception as err:
                log.error(f"Exception {err}")

    def rsyncpoller(self):
        for manifest, repository in self.rsynclist[None]:
            repourl = urllib.parse.urlparse(repository)
            rpath = os.path.basename(os.path.dirname(repourl.path))
            repopath = os.path.join(self.rpkifiledir, rpath)
            self.process_rsync(manifest, repository, repopath)

    def get_manifest(self, rpki_manifest, rsync=False):
        mfurl = urllib.parse.urlparse(rpki_manifest)
        rpath = Path(mfurl.path).parts
        if rsync:
            manifestfile = os.path.join(self.rpkifiledir, *rpath[1:])
        else:
            manifestfile = os.path.join(self.rrdpfiledir, *rpath[1:])
        return manifestfile

    def get_rsync_repository(self, ca_repository):
        return self.get_repository(ca_repository, True, -1)

    def get_repository(self, ca_repository, rsync=False, pathlen=None):
        u = urllib.parse.urlparse(ca_repository)
        rpath = Path(u.path).parts
        log.debug(f"FS path is {rpath[1:pathlen]} {rpath}")
        if rsync:
            repopath = os.path.join(self.rpkifiledir, *rpath[1:pathlen])
        else:
            repopath = os.path.join(self.rrdpfiledir, *rpath[1:pathlen])
        return repopath

    def get_number_of_repositories(self):
        return self.num_elements(self.rrdplist)

    def num_elements(self, x):
        if isinstance(x, dict):
            return sum([self.num_elements(_x) for _x in x.values()])
        else:
            return 1
