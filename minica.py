#!/usr/bin/env python
import os
import subprocess
import re
import logging


class MiniCA:
    class Error(Exception):
        def __init__(self, message):
            self.message = message
        def __str__(self):
            return 'MiniCA.Error: ' + self.message

    def __init__(self, root):
        self.root = root
        self.logger = logging.getLogger('%s(%s)' % (self.__class__.__name__, root))

    def exec_openssl(self, *args, **kwargs):
        stdin_data=kwargs.pop('stdin_data', None)
        args = ['openssl'] + list(args)
        self.logger.debug('exec_openssl: %r', args)
        proc = subprocess.Popen(
            args=args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                'ROOT': self.get_path(),
                'OPENSSL_CONF': os.path.abspath(os.path.join(os.path.dirname(__file__), 'openssl.cnf'))
            }
        )
        (stdout, stderr) = proc.communicate(stdin_data)
        proc.wait()
        if proc.returncode != 0:
            raise MiniCA.Error("error calling openssl:\n" + stderr)
        return (proc.returncode, stdout, stderr)

    def get_path(self, *args):
        return os.path.join(self.root, *args)

    def validate_name(self, value):
        if not re.match('^[a-zA-Z0-9\.\@]+$', value):
            raise MiniCA.Error('invalid name: %r' % (value, ))
        return value

    def validate_string(self, value):
        if not re.match('^[^/]+$', value):
            raise MiniCA.Error('invalid string: %r' % (value, ))
        return value

    def encode_subject(self, args):
        fields = [('C', 'country'), ('ST', 'state'), ('L', 'location'), ('O', 'organization'), ('OU', 'organizationalUnit'), ('CN', 'commonName')]
        extra_fields = set(args.keys()) - set([v for (k, v) in fields])
        if extra_fields:
            raise MiniCA.Error('subject has extra field: %r' % (extra_fields, ))
        subj = ['']
        for (k, v) in fields:
            if v in args:
                subj.append(k+'='+args[v].encode('string-escape').replace('/', '\\/'))
        subj = '/'.join(subj)
        return subj

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

    def get_csr_info(self, csr):
        res = self.exec_openssl(
            'req', '-text', '-noout', '-verify', '-in', '-',
            stdin_data=csr
        )
        print res
        pass


    def sign(self, csr):
        # max_days?
        # force_usage?
        self.exec_openssl(
            'ca',
            '-extensions', 'usr_cert',
            '-days', 375,
            'notext',
            '-md', 'sha256',
            '-batch',
            '-in', ''
            '-out', ''
        )

    def create_and_sign(self, commonName, subj=None):
        self.validate_name(commonName)
        if subj is None:
            subj = {}
        subj['commonName'] = commonName
        self.exec_openssl(
            'genrsa'
            '-out', self.get_path('private', commonName+'.key.pem'),
            '2048'
        )
        self.exec_openssl(
            'req',
            '-utf8', '-batch', '-new', '-sha256',
            '-subj', self.encode_subject(subj),
            '-key', self.get_path('private', commonName+'.key.pem'),
            '-out', self.get_path('csr', commonName+'.csr.pem')
        )

        self.get_csr_info(self.get_csr(commonName))
        # self.sign(self.get_csr(commonName))
        # -multivalue-rdn ?
        # -extensions?
        # -reqexts?
        pass

    def get_csr(self, commonName):
        with open(self.get_path('csr', commonName + '.csr.pem'), 'r') as fp:
            return fp.read()

    def get_certificate(self, commonName):
        with open(self.get_path('certs', commonName + '.cert.pem'), 'r') as fp:
            return fp.read()

    def get_key(self, commonName):
        with open(self.get_path('private', commonName + '.key.pem'), 'r') as fp:
            return fp.read()

    def get_key_and_certificate(self, commonName):
        return self.get_certificate(commonName) + self.get_key(commonName)

    def get_ca_certificate(self):
        with open(self.get_path('certs', 'ca.cert.pem'), 'r') as fp:
            return fp.read()




if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ca = MiniCA(
        root=os.path.abspath(os.path.join(__file__, '..', 'data'))
        # location/etc. subj?
    )
    ca.initialize() # auto!
    ca.create_and_sign('client1.example.net')



