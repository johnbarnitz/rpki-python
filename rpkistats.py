class StatsObject(object):
    def __init__(self):

        self.roas = 0
        self.failedroas  =0
        self.invalidroas = 0
        self.certificates = 0
        self.failcertificates = 0
        self.invalidcertificates = 0
        self.manifests = 0
        self.failedmanifests = 0
        self.stalemanifests = 0
        self.crls = 0
        self.gbrs = 0
        self.repositories = 0
        self.uniquevrps = 0
        self.cachedir_del_files = 0
        self.cachedir_del_dirs = 0


    def updatestats(self,r):
        self.roas += r.numroas
        self.failedroas  += r.numfailedroas
        self.invalidroas += r.numinvalidroas
        self.certificates += r.numcertificates
        self.failcertificates += r.numfailedcertificates
        self.invalidcertificates += r.numinvalidcertificates
        self.manifests += r.nummanifests
        self.failedmanifests += r.numfailedmanifests
        self.stalemanifests += r.numstalemanifests
        self.crls += r.numcrls
        self.gbrs += r.numgbrs
        self.repositories += r.get_number_of_repositories()
