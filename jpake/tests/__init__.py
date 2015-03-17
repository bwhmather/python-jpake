import unittest

from jpake import JPAKE


class JPAKETestCase(unittest.TestCase):
    def test_basic(self):
        secret = "hunter42"
        alice = JPAKE(secret=secret, signer_id=b"alice")
        bob = JPAKE(secret=secret, signer_id=b"bob")

        alice.process_one(bob.one()), bob.process_one(alice.one())

        alice.process_two(bob.two()), bob.process_two(alice.two())


loader = unittest.TestLoader()
suite = unittest.TestSuite((
    loader.loadTestsFromTestCase(JPAKETestCase),
))
