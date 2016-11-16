#!/usr/bin/env python
import os
import subprocess

class MiniCA:
    class Error(Exception):
        def __init__(self, message):
            self.message = message
        def __str__(self):
            return 'MiniCA.Error: ' + self.message

    def __init__(self, root):
        self.root = root

    def exec_openssl(self, *args):
        openssl_cnf = os.path.abspath(os.path.join(os.path.dirname(__file__), 'openssl.cnf'))
        args = ['openssl'] + list(args)
        args = args[0:2] + ['-config', openssl_cnf] + args[2:]
        proc = subprocess.Popen(
            args=args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.get_path(),
            env={
                'ROOT': self.get_path()
            }
        )
        (stdout, stderr) = proc.communicate(None)
        proc.wait()
        if proc.returncode != 0:
            raise MiniCA.Error("error calling openssl:\n" + stderr)
        return (proc.returncode, stdout, stderr)

    def get_path(self, *args):
        return os.path.join(self.root, *args)

    def initialize(self):
        if not os.path.isdir(self.get_path()):
            os.mkdir(self.get_path())
        for i in ['certs', 'crl', 'newcerts', 'private']:
            d = self.get_path(i)
            if not os.path.isdir(d):
                os.mkdir(d)
        os.chmod(self.get_path('private'), 0700)

        if not os.path.isfile(self.get_path('private', 'ca.key.pem')):
            self.exec_openssl(
                'genrsa',
                '-out', self.get_path('private', 'ca.key.pem'),
                '4096'
            )

        if not os.path.isfile(self.get_path('certs', 'ca.cert.pem')):
            self.exec_openssl(
                'req',
                '-subj', '/C=DE/ST=Germany/L=Germany/O=private/CN=ca',
                '-key', self.get_path('private', 'ca.key.pem'),
                '-new', '-x509', '-days', '7300', '-sha256', '-extensions', 'v3_ca',
                '-out', self.get_path('certs', 'ca.cert.pem')
            )


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
    ca = MiniCA(
        root=os.path.abspath(os.path.join(__file__, '..', 'data'))
    )
    ca.initialize()


