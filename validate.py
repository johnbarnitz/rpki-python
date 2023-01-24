#!/usr/bin/env python3
import sys

from RRDPCollector import RRDPCollector
import json
import logging
import os
import pickle
import gc
import platform
from datetime import datetime
from resource import getrusage as resource_usage, RUSAGE_SELF
from time import time as timestamp
from rpkistats import StatsObject
import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description='Return aliases of all the subscribers of a list.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-l", "--log_file_name",
                        dest="logfilename",
                        help="File for log output",
                        required=False)
    parser.add_argument("-r", "--rpki_file_dir",
                        dest="rpkifiledir",
                        help="Directory to place all downloaded rpki files",
                        required=True)
    parser.add_argument("-t", "--tal_dir",
                        dest="taldir",
                        help="Directory where the TAL files are located",
                        required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    start_time, start_resources = timestamp(), resource_usage(RUSAGE_SELF)
    if args.logfilename:
        logging.basicConfig(
                filename=args.logfilename,
                stream=sys.stdout,
                format='%(asctime)s %(levelname)-8s %(message)s',
                level=logging.ERROR,
                datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(
                stream=sys.stdout,
                format='%(asctime)s %(levelname)-8s %(message)s',
                level=logging.ERROR,
                datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(__name__)

    log.info("Starting Validator")
    rpkifiledir = args.rpkifiledir
    if not os.path.exists(rpkifiledir + "/rrdp"):
        os.makedirs(rpkifiledir + "/rrdp")
    taldir = args.taldir
    talfiles = ["afrinic.tal", "apnic.tal", "arin.tal", "lacnic.tal", "ripe-ncc.tal"]

    validroa_recurse = []
    allroas = {}
    stat = StatsObject()
    for talf in talfiles:
        log.info(f"Starting Tal {talf}")
        try:
            r = RRDPCollector(talf, rpkifiledir, taldir)
        except Exception as err:
            log.error(f"Could not initialize tal repository ")
            continue

        log.debug("Tal loaded")
        r.start()
        allroas[talf] = r.validROA
        stat.updatestats(r)
        del r
        gc.collect()
    end_resources, end_time = resource_usage(RUSAGE_SELF), timestamp()
    log.debug(json.dumps(allroas))
    with open(f"roas.bin", "wb") as f:
        pickle.dump(allroas, f)

    roajson = {"metadata": {}, "roas": []}
    roajson["metadata"]["buildmachine"] = platform.uname()[1]
    roajson["metadata"]["buildtime"] = str(datetime.now())

    real = end_time - start_time
    sys = end_resources.ru_stime - start_resources.ru_stime
    user = end_resources.ru_utime - start_resources.ru_utime

    roajson["metadata"]["elapsedtime"] = real
    roajson["metadata"]["usertime"] = user
    roajson["metadata"]["systemtime"] = sys
    roajson["metadata"]["tals"] = len(talfiles)
    roajson["metadata"]["talfiles"] = ",".join(talfiles)

    roajson["metadata"] = vars(stat)

    for t in allroas.keys():
        for v in allroas[t]:
            j = allroas[t][v]
            for k in j[0]['ipaddrs']:
                rv = {"asn": j[0]['asn'], "prefix": k[0], "maxLength": k[1], "ta": t, "expires": j[1]}
                roajson['roas'].append(rv)
    roajson["metadata"]["vrps"] = len(roajson["roas"])
    with open("vrp_file.json", "w") as write_file:
        json.dump(roajson, write_file)
