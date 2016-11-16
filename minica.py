#!/usr/bin/env python
import os

class minica:
    def __init__(self, root):
        self.root = root
        # other arguments...

    def initialize(self):
        if not os.path.isdir(self.root):
            os.mkdir(self.root)
        for i in ['certs', 'crl', 'newcerts', 'private']:
            d = os.path.join(self.root, i)
            if not os.path.isdir(d):
                os.mkdir(d)
        os.chmod(os.path.join(self.root, 'private'), 0700)

    def sign(self, csr):
        pass

    def create_and_sign(self, cname):
        pass

    def get_certificate(self, name):
        pass

    def get_key(self, name):
        pass

    def get_key_and_certificate(self, name):
        pass

    def get_ca_certificate(self):
        pass




if __name__ == '__main__':
    ca = minica(
        root=os.path.abspath(os.path.join(__file__, '..', 'data'))
    )
    ca.initialize()


