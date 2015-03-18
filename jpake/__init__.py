from random import SystemRandom
from hashlib import sha1
from enum import IntEnum

from jpake.parameters import NIST_80, NIST_112, NIST_128


class DuplicateSignerError(Exception):
    pass


class InvalidProofError(Exception):
    pass


class OutOfSequenceError(Exception):
    pass


def _from_bytes(bs):
    return int.from_bytes(bs, 'big')


def _to_bytes(num):
    return num.to_bytes((num.bit_length() // 8) + 1, byteorder='big')


class JPAKE(object):
    class _State(IntEnum):
        waiting_one = 1
        waiting_secret = 2
        waiting_two = 3
        completed = 4

    @property
    def secret(self):
        return self._secret

    @secret.setter
    def secret(self, value):
        if value is None:
            raise ValueError()
        if self._state > self._State.waiting_secret:
            raise Exception()
        if self._state == self._State.waiting_secret:
            self._state = self._State.waiting_two

        # TODO TODO TODO this is probably not the correct behaviour
        if isinstance(value, str):
            value = value.encode('utf-8')
        if isinstance(value, bytes):
            value = _from_bytes(value)
        self._secret = value

    def __init__(
            self, *, x1=None, x2=None, secret=None,
            gx3=None, gx4=None, B=None,
            parameters=NIST_128, random=None, signer_id=None):
        if random is None:
            random = SystemRandom()
        self._rng = random

        if isinstance(signer_id, str):
            signer_id = signer_id.encode('utf-8')
        if signer_id is None:
            signer_id = bytes(self._rng.getrandbits(16))
        self.signer_id = signer_id

        self.p = parameters.p
        self.g = parameters.g
        self.q = parameters.q

        # Setup hidden state
        if x1 is None:
            x1 = self._rng.randrange(self.q)
        self.x1 = x1

        if x2 is None:
            x2 = self._rng.randrange(1, self.q)
        self.x2 = x2

        # Step one
        self.gx1 = pow(self.g, self.x1, self.p)
        self.gx2 = pow(self.g, self.x2, self.p)

        self.zkp_x1 = self._zkp(self.g, self.x1, self.gx1)
        self.zkp_x2 = self._zkp(self.g, self.x2, self.gx2)

        self._state = self._State.waiting_one

        # Resume from after step one
        if gx3 is not None and gx4 is None:
            raise ValueError("only gx3 provided")
        if gx3 is None and gx4 is not None:
            raise ValueError("only gx4 provided")

        if gx3 is not None:
            self.process_one(gx3=gx3, gx4=gx4, verify=False)

        # Resume from after setting secret
        if secret is not None:
            self.secret = secret

        # Resume from after step two
        if B is not None:
            self.process_two(B=B, verify=False)

    def _zkp_hash(self, *, generator, gr, gx, signer_id):
        # TODO not part of core algorithm
        # implementation is compatible with openSSL but deserves a better look
        # https://github.com/openssl/openssl/blob/master/crypto/jpake/jpake.c#L166
        def pascal(s):
            """Encode a byte string as a pascal string with a big-endian header
            """
            if len(s) > 2**16:
                raise Exception()
            return len(s).to_bytes(2, 'big')

        s = b"".join((
            pascal(_to_bytes(generator)),
            pascal(_to_bytes(gr)),
            pascal(_to_bytes(gx)),
            pascal(signer_id)
        ))
        return _from_bytes(sha1(s).digest())

    def _zkp(self, generator, exponent, gx=None):
        """Returns a proof that can be used by someone who only has knowledge
        of ``generator`` and ``p`` that we have a value for ``exponent`` that
        satisfies the equation ``generator^exponent=B mod p``
        """
        p = self.p
        q = self.q

        if gx is None:
            gx = pow(generator, exponent, p)
        r = self._rng.randrange(q)
        gr = pow(generator, r, p)
        h = self._zkp_hash(
            generator=generator, gr=gr, gx=gx, signer_id=self.signer_id
        )
        b = (r - exponent*h) % q
        return {
            'gr': gr,
            'b': b,
            'id': self.signer_id,
        }

    def _verify_zkp(self, generator, gx, zkp):
        """Verify that the senders proof that they know ``x`` such that
        ``generator^{x} mod p = gx`` holds.
        """
        p = self.p
        gr = zkp['gr']
        b = zkp['b']

        if zkp['id'] == self.signer_id:
            raise DuplicateSignerError()
        h = self._zkp_hash(
            generator=generator, gr=gr, gx=gx, signer_id=zkp['id']
        )
        gb = pow(generator, b, p)
        y = pow(gx, h, p)
        if gr != (gb*y) % p:
            raise InvalidProofError()

    def process_one(
            self, data=None, *, verify=True,
            gx3=None, gx4=None, zkp_x3=None, zkp_x4=None):
        """Read in the values from the another step one and perform step two

        Accepts either a dictionary of values in the form produced by ``one``
        or the required values passed in individually as keyword arguments.

        :param data: A dictionary containing the results of running step one at
            the other end of the connection.

            Should use the naming convention of the other party. ``data["x1"]``
            will be assigned to ``x3``, likewise for ``x2``, ``zkp_x1`` and
            ``zkp_x2``.

        :param gx3: ``g^{x3}``
        :param gx4: ``g^{x4}``
        :param zjp_x3: Proof that ``x3`` is known by the caller.
        :param zjp_x4: Proof that ``x4`` is known by the caller.

        :param verify: If ``False`` then ``zkp_x3`` and ``zkp_x4`` are ignored
            and proof verification is skipped.

        :raises OutOfSequenceError: If called more than once.
        :raises ValueError: If passed both a data dictionary and step one as
            keyword arguments.
        :raises InvalidProofError: If verification is enabled and either of
            the proofs fail
        """
        p = self.p
        g = self.g

        if self._state is not self._State.waiting_one:
            raise OutOfSequenceError(self._State.waiting_one, self._state)

        if data is not None:
            if any(param is not None for param in (gx3, gx4, zkp_x3, zkp_x4)):
                raise ValueError("unexpected keyword argument")
            gx3 = data['gx1']
            gx4 = data['gx2']

            zkp_x3 = data['zkp_x1']
            zkp_x4 = data['zkp_x2']

        # we need to at least check this for ``gx4`` in order to prevent
        # callers sneaking in ``gx4 mod p`` equal to 1
        gx3 %= p
        gx4 %= p

        if gx4 == 1:
            raise ValueError()

        if verify:
            self._verify_zkp(g, gx3, zkp_x3)
            self._verify_zkp(g, gx4, zkp_x4)

        # A = g^((x1+x3+x4)*x2*s)
        #   = (g^x1*g^x3*g^x4)^(x2*s)
        t1 = (((self.gx1 * gx3) % p) * gx4) % p
        t2 = (self.x2 * self.secret) % p

        A = pow(t1, t2, p)

        # zero knowledge proof for ``x2*s``
        zkp_A = self._zkp(t1, t2, A)

        if self.secret is None:
            self._state = self._State.waiting_secret
        else:
            self._state = self._State.waiting_two

        self.gx3 = gx3
        self.gx4 = gx4

        self.A = A
        self.zkp_A = zkp_A

    def process_two(self, data=None, *, B=None, zkp_B=None, verify=False):
        p = self.p
        q = self.q

        if self._state is not self._State.waiting_two:
            raise OutOfSequenceError(self._State.waiting_two, self._state)

        if data is not None:
            if B is not None or zkp_B is not None:
                raise ValueError("unexpected keyword argument")
            B = data['A']
            zkp_B = data['zkp_A']

        if verify:
            generator = (((self.gx1*self.gx2) % p) * self.gx3) % p
            self._verify_zkp(generator, B, zkp_B)

        # t3 = g^-(x4*x2*s)
        #    = (g^x4)^(x2*-s)
        bottom = pow(self.gx4, self.x2 * (q - self.secret), p)

        # t4 = B/(g^(x4*x2*s))
        #    = B*t3
        inner = (B * bottom) % p

        # K = (B/(g^(x4*x2*s)))^x2
        K = pow(inner, self.x2, p)

        self._state = self._State.completed

        # TODO Key derivation function is necessary to avoid exposing K but the
        # spec does not fix one and the choice of function depends on the
        # application.  Possibly choose one that can be adjusted to output a
        # key of approximately the same number of bits
        self.K = K

    def one(self):
        return {
            'gx1': self.gx1,
            'zkp_x1': self.zkp_x1,
            'gx2': self.gx2,
            'zkp_x2': self.zkp_x2,
        }

    def two(self):
        return {
            'A': self.A,
            'zkp_A': self.zkp_A,
        }


__all__ = ['NIST_80', 'NIST_112', 'NIST_128', 'JPAKE']
