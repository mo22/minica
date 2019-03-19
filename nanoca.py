#!/usr/bin/env python

import os
import subprocess
import re
import logging

__all__ = ['NanoCA']
__version__ = '0.8'
__author = 'Moritz Moeller <mm@mxs.de>'

openssl_cnf_template = """
RANDFILE          = $ENV::ROOT/private/.rnd

[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ENV::ROOT
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rnd
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose
email_in_dn       = no
copy_extensions   = copy

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address
#countryName_default             = GB
#stateOrProvinceName_default     = England
#localityName_default            =
#0.organizationName_default      = Alice Ltd
#organizationalUnitName_default =
#emailAddress_default           =

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ user_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
crlDistributionPoints = URI:http://example.com/intermediate.crl.pem

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
"""

class NanoCA:
    """
    NanoCA class
    """

    class Error(Exception):
        def __init__(self, message):
            self.message = message
        def __str__(self):
            return 'NanoCA.Error: ' + self.message

    # --

    def __init__(self, root):
        """
        initialize the CA
        :param root: base path for the CA
        :type root: str or unicode
        """
        self.root = root
        self.logger = logging.getLogger('%s.%s' % (self.__class__.__name__, root))
        self.initialize()

    # --

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
                'OPENSSL_CONF': self.get_path('openssl.cnf')
            }
        )
        (stdout, stderr) = proc.communicate(stdin_data)
        stderr = stderr.decode('utf-8')
        proc.wait()
        self.logger.debug('exec_openssl: exitcode=%r stdout=%r stderr=%r', proc.returncode, stdout, stderr)
        if proc.returncode != 0:
            raise NanoCA.Error("error calling openssl:\n" + stderr)
        return stdout

    # --

    def get_path(self, *args):
        return os.path.join(self.root, *args)

    # --

    def validate_name(self, value):
        if not re.match('^[a-zA-Z0-9\-\.\@]+$', value):
            raise NanoCA.Error('invalid name: %r' % (value, ))
        return value

    def validate_string(self, value):
        if not re.match('^[^/]+$', value):
            raise NanoCA.Error('invalid string: %r' % (value, ))
        return value

    # --

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
            raise NanoCA.Error('subject has extra field: %r' % (extra_fields, ))
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
                raise NanoCA.Error('cannot decode field: %r' % (k, ))
            res[self.subject_fields[k]] = v
        return res

    # --

    def initialize(self):
        try:
            self.exec_openssl('version')
        except:
            raise NanoCA.Error('openssl binary not found')

        if not os.path.isdir(self.get_path()):
            os.mkdir(self.get_path())
        if not os.path.isfile(self.get_path('openssl.cnf')):
            with open(self.get_path('openssl.cnf'), 'w') as fp:
                fp.write(openssl_cnf_template)
        for i in ['certs', 'crl', 'newcerts', 'private', 'all']:
            d = self.get_path(i)
            if not os.path.isdir(d):
                os.mkdir(d)
        os.chmod(self.get_path('private'), 0o700)
        if not os.path.isfile(self.get_path('index.txt')):
            with open(self.get_path('index.txt'), 'w') as fp:
                pass
        if not os.path.isfile(self.get_path('index.txt.attr')):
            with open(self.get_path('index.txt.attr'), 'w') as fp:
                pass
        if not os.path.isfile(self.get_path('serial')):
            with open(self.get_path('serial'), 'w') as fp:
                fp.write('1000\n')
        if not os.path.isfile(self.get_path('crlnumber')):
            with open(self.get_path('crlnumber'), 'w') as fp:
                fp.write('1000\n')
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

    def get_ca_certificate(self):
        """
        :returns: the CA certiciate in PEM format
        :rtype: str
        """
        with open(self.get_path('certs', 'ca.cert.pem'), 'r') as fp:
            return fp.read()

    def get_csr_info(self, csr):
        res = self.exec_openssl(
            'req', '-subject', '-noout', '-text', '-verify', stdin_data=csr
        )
        m = re.search('subject=(.*)', res)
        if not m:
            raise NanoCA.Error('cannot parse response')
        return self.decode_subject(m.group(1))

    def extract_key(self, pem):
        return self.exec_openssl(
            'rsa',
            stdin_data=pem
        )

    def extract_cert(self, pem):
        return self.exec_openssl(
            'x509',
            stdin_data=pem
        )

    def extract_csr(self, pem):
        return self.exec_openssl(
            'req',
            stdin_data=pem
        )

    def sign(self, csr, store=True, days=None, extensions=None):
        """
        sign csr (in pem format) and return certificate (in pem format)
        """
        days = int(days or 365)
        extensions = extensions or ['server_cert']
        self.logger.info('sign')
        info = self.get_csr_info(csr)
        self.logger.info('sign commonName=%r', info['commonName'])
        res = self.exec_openssl(
            'ca',
            '-notext',
            '-md', 'sha256',
            '-batch',
            '-in', '/dev/stdin',
            '-out', '/dev/stdout',
            '-days', str(days),
            '-extensions', ','.join(extensions),
            stdin_data=csr
        )
        if store:
            with open(self.get_path('all', info['commonName']+'.cert.pem'), 'w') as fp:
                fp.write(res)
        return res

    def get_crl(self):
        return self.exec_openssl('ca', '-gencrl')

    def revoke(self, cert):
        self.exec_openssl(
            'ca', '-revoke', '/dev/stdin',
            stdin_data=cert
        )

    def create_and_sign(self, commonName, subj=None, store=True, days=None, extensions=None):
        self.logger.info('create_and_sign commonName=%r subj=%r', commonName, subj)
        self.validate_name(commonName)
        if subj is None:
            subj = {}
        subj['commonName'] = commonName
        csr_and_key = self.exec_openssl(
            'req',
            '-utf8', '-batch', '-new', '-sha256',
            '-subj', self.encode_subject(subj),
            '-newkey', 'rsa:2048', '-nodes'
        )
        csr = self.extract_csr(csr_and_key)
        key = self.extract_key(csr_and_key)
        cert = self.sign(csr, store=store, days=days, extensions=extensions)
        if store:
            with open(self.get_path('all', commonName+'.key.pem'), 'w') as fp:
                fp.write(key)
            with open(self.get_path('all', commonName+'.csr.pem'), 'w') as fp:
                fp.write(csr)
        return cert + key

    # --

    def get_certificate(self, commonName):
        p = self.get_path('all', commonName + '.cert.pem')
        if not os.path.isfile(p):
            raise NanoCA.Error('certificate for %r does not exist' % (commonName, ))
        with open(p, 'r') as fp:
            return fp.read()

    def get_key(self, commonName):
        """
        :param commonName: name of key to return
        :type commonName: str
        :returns: the key in PEM format
        :rtype: str
        """
        p = self.get_path('all', commonName + '.key.pem')
        if not os.path.isfile(p):
            raise NanoCA.Error('key for %r does not exist' % (commonName, ))
        with open(p, 'r') as fp:
            return fp.read()

    def get_key_and_certificate(self, commonName):
        return self.get_certificate(commonName) + self.get_key(commonName)




def main():
    import os
    import sys
    import argparse

    def do_cacert(args):
        sys.stdout.write(ca.get_ca_certificate())

    def do_crl(args):
        sys.stdout.write(ca.get_crl())

    def do_cert(args):
        sys.stdout.write(ca.get_certificate(args.commonName))

    def do_key(args):
        sys.stdout.write(ca.get_key(args.commonName))

    def do_certkey(args):
        sys.stdout.write(ca.get_certificate(args.commonName))
        sys.stdout.write(ca.get_key(args.commonName))

    def do_sign(args):
        csr = sys.stdin.read()
        res = ca.sign(csr, days=args.days, extensions=[args.usage])
        if args.show:
            sys.stdout.write(res)

    def do_revoke(args):
        if args.commonName:
            cert = ca.get_certificate(args.commonName)
        else:
            cert = sys.stdin.read()
        ca.revoke(cert)

    def do_create(args):
        ca.create_and_sign(args.commonName, days=args.days, extensions=[args.usage])
        if args.show:
            sys.stdout.write(ca.get_certificate(args.commonName))
            sys.stdout.write(ca.get_key(args.commonName))

    parser = argparse.ArgumentParser(description='NanoCA')
    parser.add_argument('--root', help='root directory for CA')
    parser.add_argument('--verbose', action='store_true', default=False, help='verbose mode')
    subparsers = parser.add_subparsers(help='sub-command help')

    parser_cacert = subparsers.add_parser('cacert', help='write ca cert to stdout in pem format')
    parser_cacert.set_defaults(func=do_cacert)

    parser_crl = subparsers.add_parser('crl', help='write crl to stdout in pem format')
    parser_crl.set_defaults(func=do_crl)

    parser_cert = subparsers.add_parser('cert', help='write certificate to stdout in pem format')
    parser_cert.add_argument('commonName', help='common name of certificate')
    parser_cert.set_defaults(func=do_cert)

    parser_key = subparsers.add_parser('cert', help='write key to stdout in pem format')
    parser_key.add_argument('commonName', help='common name of certificate')
    parser_key.set_defaults(func=do_key)

    parser_certkey = subparsers.add_parser('certkey', help='write certificate and key to stdout in pem format')
    parser_certkey.add_argument('commonName', help='common name of certificate')
    parser_certkey.set_defaults(func=do_certkey)

    parser_sign = subparsers.add_parser('sign', help='sign a csr')
    parser_sign.add_argument('--days', default='365', help='days of validity')
    parser_sign.add_argument('--usage', default='server_cert', help='usage, server_cert or user_cert')
    parser_sign.add_argument('--show', default=False, action='store_true', help='print result')
    parser_sign.set_defaults(func=do_sign)

    parser_revoke = subparsers.add_parser('revoke', help='revoke a certificate')
    parser_revoke.add_argument('commonName', nargs='?', help='common name of certificate, otherwise stdin is used')
    parser_revoke.set_defaults(func=do_revoke)

    parser_create = subparsers.add_parser('create', help='create csr and sign')
    parser_create.add_argument('commonName', help='common name of certificate')
    parser_create.add_argument('--days', default='365', help='days of validity')
    parser_create.add_argument('--usage', default='server_cert', help='usage, server_cert or user_cert')
    parser_create.add_argument('--show', default=False, action='store_true', help='print result')
    parser_create.set_defaults(func=do_create)

    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        sys.exit(1)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    root = os.path.abspath(os.path.join(__file__, '..', 'data'))
    if 'NANOCA_ROOT' in os.environ:
        root = os.environ['NANOCA_ROOT']
    if args.root:
        root = args.root
    ca = NanoCA(
        root=root
    )

    args.func(args)


if __name__ == '__main__':
    main()

