#!/usr/bin/env python

import sys
import base64
import urllib.parse

class tal:

    def __init__(self,value=None):
        self.uri = []
        self.key = b''
        if value is not None:
            self.set(value)
    def set(self,value):
        #Read in tal file
        with open(value, "r") as f:
            content = [i.strip() for i in f.readlines()]
        foundnewline = False
        urllist = []
        keylist = []
        for line in content:
            if line.startswith("#"):
                continue
            if line== "":
                foundnewline = True
            else:
                if foundnewline:
                    keylist.append(line)
                else:
                    urllist.append(line)
        for u in urllist:
            urlobj = urllib.parse.urlparse(u)
            self.uri.append(urlobj)
            print (urlobj)
        keystr = ''.join(keylist)

        self.key = base64.b64decode(keystr)

#print(base64.b64decode(keystr))
