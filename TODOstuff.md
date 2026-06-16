TODO:

- ADDED authentication, password hashing etc DONE
        -- NEED TO CREATE TESTS FOR
- ADDED password changing

- add mutual TLS, temp CA
        - add Extended Key Usage for mutualTLS , restrict what certs can be used for
        - need to figure out how to distribute certs, (make on server dist manually?)
- add setup.py instead of using 'sys.path.insert(0, str(Path(__file__).resolve().parent.parent))'
        --> from setuptools import setup, find_packages