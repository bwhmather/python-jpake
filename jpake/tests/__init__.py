import unittest

from jpake import JPAKE


class JPAKETestCase(unittest.TestCase):
    def test_basic(self):
        secret = "hunter42"
        alice = JPAKE(secret=secret, signer_id=b"alice")
        bob = JPAKE(secret=secret, signer_id=b"bob")

        alice.process_one(bob.one()), bob.process_one(alice.one())

        alice.process_two(bob.two()), bob.process_two(alice.two())

    def test_skip_verification_one(self):
        secret = "hunter42"
        alice = JPAKE(secret=secret, signer_id=b"alice")
        bob = JPAKE(secret=secret, signer_id=b"bob")

        bob_one = bob.one()

        alice.process_one(gx3=bob_one['gx1'], gx4=bob_one['gx2'], verify=False)

    def test_no_proofs_one(self):
        secret = "hunter42"
        alice = JPAKE(secret=secret, signer_id=b"alice")
        bob = JPAKE(secret=secret, signer_id=b"bob")

        bob_one = bob.one()

        self.assertRaises(
            Exception, alice.process_one,
            gx3=bob_one['gx1'], gx4=bob_one['gx2']
        )

    def test_skip_verification_on_dict(self):
        secret = "hunter42"
        alice = JPAKE(secret=secret, signer_id=b"alice")
        bob = JPAKE(secret=secret, signer_id=b"bob")

        self.assertRaises(
            ValueError, alice.process_one, bob.one(), verify=False
        )

    def test_secret_after_process_one(self):
        secret = "hunter42"
        alice = JPAKE(signer_id=b"alice")
        bob = JPAKE(signer_id=b"bob")

        alice.process_one(bob.one()), bob.process_one(alice.one())

        alice.secret = secret
        bob.secret = secret

        alice.process_two(bob.two()), bob.process_two(alice.two())


loader = unittest.TestLoader()
suite = unittest.TestSuite((
    loader.loadTestsFromTestCase(JPAKETestCase),
))
