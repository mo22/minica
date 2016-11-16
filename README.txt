TODO:
[ ] rename, pip
    #python setup.py register -r pypi
    #python setup.py sdist upload -r pypi
[ ] this doc!
[ ] inline docs

http://stackoverflow.com/questions/5334531/using-javadoc-for-python-documentation
https://jamielinux.com/docs/openssl-certificate-authority/


CLI USAGE:

python nanoca.py create [name] --days 365 --usage server_cert
python nanoca.py sign ...
python nanoca.py cacert ...
python nanoca.py cert name ...


API USAGE:

import nanoca
ca = nanoca.NanoCA(root='some_dir')
ca.create('test.example.net')
ca.get_key('test.example.net')
ca.get_cert('test.example.net')



