todo...

python minica.py create [name] --days 365 --usage server_cert
python minica.py sign ...
python minica.py cacert ...
python minica.py cert name ...


import minica
ca = minica.MiniCA(root='some_dir')
ca.create('test.example.net')
ca.get_key('test.example.net')
ca.get_cert('test.example.net')


#python setup.py register -r pypi
#python setup.py sdist upload -r pypi

