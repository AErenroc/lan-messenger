TODO:

- add authentication, password hashing etc DONE
        -- NEED TO CREATE TESTS FOR
- add mutual TLS, temp CA
- add setup.py instead of using 'sys.path.insert(0, str(Path(__file__).resolve().parent.parent))'
        --> from setuptools import setup, find_packages