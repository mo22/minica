#!/usr/bin/env python

"""
[ ] docs: http://stackoverflow.com/questions/5334531/using-javadoc-for-python-documentation
[ ] github
[ ] cli

"""

import os
import subprocess
import re
import logging

__all__ = ['MiniCA']
__version__ = '0.1'
__author = 'Moritz Moeller <mm@mxs.de>'

class MiniCA:
    """
    MiniCA class
    """

    class Error(Exception):
        def __init__(self, message):
            self.message = message
        def __str__(self):
            return 'MiniCA.Error: ' + self.message

    def __init__(self, root):
        """
        initialize the CA
        :param root: base path for the CA
        :type root: str or unicode
        """
        self.root = root
        self.logger = logging.getLogger('%s(%s)' % (self.__class__.__name__, root))
        self.initialize()

    def exec_openssl(self, *args, **kwargs):
        stdin_data=kwargs.pop('stdin_data', None)
        args = ['openssl'] + list(args)
        self.logger.debug('exec_openssl: %r', args)
        if stdin_data:
            self.logger.debug('exec_openssl: stdin_data=%r', stdin_data)
        proc = subprocess.Popen(
            args=args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                'ROOT': self.get_path(),
                'OPENSSL_CONF': os.path.abspath(os.path.join(os.path.dirname(__file__), 'openssl.cnf'))
            }
        )
        (stdout, stderr) = proc.communicate(stdin_data)
        proc.wait()
        self.logger.debug('exec_openssl: exitcode=%r stdout=%r stderr=%r', proc.returncode, stdout, stderr)
        if proc.returncode != 0:
            raise MiniCA.Error("error calling openssl:\n" + stderr)
        return stdout

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

    subject_fields = {
        'C': 'country',
        'ST': 'state',
        'L': 'locality',
        'O': 'organization',
        'OU': 'organizationalUnit',
        'CN': 'commonName'
    }

    def encode_subject(self, args):
        extra_fields = set(args.keys()) - set(self.subject_fields.values())
        if extra_fields:
            raise MiniCA.Error('subject has extra field: %r' % (extra_fields, ))
        subj = ['']
        for (k, v) in self.subject_fields.items():
            if v in args:
                subj.append(k+'='+args[v].encode('string-escape').replace('/', '\\/'))
        subj = '/'.join(subj)
        return subj

    def decode_subject(self, arg):
        res = {}
        for i in arg.replace('%', '%1').replace('\\/', '%2').split('/'):
            if i == '':
                continue
            k, v = i.replace('%2', '/').replace('%1', '%').split('=', 1)
            if k not in self.subject_fields:
                raise MiniCA.Error('cannot decode field: %r' % (k, ))
            res[self.subject_fields[k]] = v
        return res

    def initialize(self):
        try:
            self.exec_openssl('version')
        except:
            raise MiniCA.Error('openssl binary not found')

        if not os.path.isdir(self.get_path()):
            os.mkdir(self.get_path())
        for i in ['certs', 'crl', 'newcerts', 'private', 'csr']:
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
            'req', '-subject', '-noout', '-text', '-verify', stdin_data=csr
        )
        m = re.search('subject=(.*)', res)
        if not m:
            raise MiniCA.Error('cannot parse response')
        return self.decode_subject(m.group(1))

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
            'genrsa',
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

        tmp = self.get_csr_info(self.get_csr(commonName))
        print tmp
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
        """
        :param commonName: name of key to return
        :type commonName: str
        :returns: the key in PEM format
        :rtype: str
        """
        with open(self.get_path('private', commonName + '.key.pem'), 'r') as fp:
            return fp.read()

    def get_key_and_certificate(self, commonName):
        return self.get_certificate(commonName) + self.get_key(commonName)

    def get_ca_certificate(self):
        """
        :returns: the CA certiciate in PEM format
        :rtype: str
        """
        with open(self.get_path('certs', 'ca.cert.pem'), 'r') as fp:
            return fp.read()




if __name__ == '__main__':
    import os
    import sys
    import argparse

    def do_cacert(args):
        sys.stdout.write(ca.get_ca_certificate())

    def do_cert(args):
        print args
        sys.stdout.write(ca.get_certificate(args.commonName))

    parser = argparse.ArgumentParser(description='MiniCA')
    parser.add_argument('--root', help='root directory for CA')
    parser.add_argument('--verbose', action='store_true', default=False, help='verbose mode')
    subparsers = parser.add_subparsers(help='sub-command help')

    parser_cacert = subparsers.add_parser('cacert', help='write ca cert to stdout in pem format')
    parser_cacert.set_defaults(func=do_cacert)

    parser_cert = subparsers.add_parser('cert', help='write certificate to stdout in pem format')
    parser_cert.add_argument('commonName', help='common name of certificate')
    parser_cert.set_defaults(func=do_cert)

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    root = os.path.abspath(os.path.join(__file__, '..', 'data'))
    if 'MINICA_ROOT' in os.environ:
        root = os.environ['MINICA_ROOT']
    if args.root:
        root = args.root
    ca = MiniCA(
        root=root
    )

    args.func(args)


