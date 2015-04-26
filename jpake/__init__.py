from types import MappingProxyType
from random import SystemRandom
from hashlib import sha1

from jpake.parameters import NIST_80, NIST_112, NIST_128

from jpake.exceptions import (
    DuplicateSignerError, InvalidProofError, OutOfSequenceError,
)


def _from_bytes(bs):
    return int.from_bytes(bs, 'big')


def _to_bytes(num):
    return num.to_bytes((num.bit_length() // 8) + 1, byteorder='big')


class JPAKE(object):
    @property
    def secret(self):
        """The shared secret

        Set during initialisation or by calling by :meth:`set_secret`

        :type: int
        """
        return self._secret

    def set_secret(self, value):
        if not self.waiting_secret:
            raise OutOfSequenceError("secret already set")

        if value is None:
            raise ValueError()

        # TODO TODO TODO this is probably not the correct behaviour
        if isinstance(value, str):
            value = value.encode('utf-8')
        if isinstance(value, bytes):
            value = _from_bytes(value)

        self._secret = value
        self.waiting_secret = False

    def __init__(
            self, *, x1=None, x2=None, secret=None,
            gx3=None, gx4=None, B=None,
            parameters=NIST_128, random=None, signer_id=None):
        if random is None:
            random = SystemRandom()
        self._rng = random

        self.waiting_secret = True
        self.waiting_one = True
        self.waiting_two = True

        if isinstance(signer_id, str):
            signer_id = signer_id.encode('utf-8')
        if signer_id is None:
            signer_id = _to_bytes(self._rng.getrandbits(16))
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

        # Resume from after step one
        if gx3 is not None and gx4 is None:
            raise TypeError("only gx3 provided")
        if gx3 is None and gx4 is not None:
            raise TypeError("only gx4 provided")

        if gx3 is not None:
            self.process_one(gx3=gx3, gx4=gx4, verify=False)

        # Resume from after setting secret
        if secret is not None:
            self.set_secret(secret)

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
            return len(s).to_bytes(2, 'big') + s

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
            raise DuplicateSignerError(zkp['id'])
        h = self._zkp_hash(
            generator=generator, gr=gr, gx=gx, signer_id=zkp['id']
        )
        gb = pow(generator, b, p)
        y = pow(gx, h, p)
        if gr != (gb*y) % p:
            raise InvalidProofError()

    def _compute_one(self):
        self._gx1 = pow(self.g, self.x1, self.p)
        self._gx2 = pow(self.g, self.x2, self.p)

        self._zkp_x1 = MappingProxyType(self._zkp(self.g, self.x1, self.gx1))
        self._zkp_x2 = MappingProxyType(self._zkp(self.g, self.x2, self.gx2))

    @property
    def gx1(self):
        """:math:`g^x1`
        :type: int
        """
        if not hasattr(self, '_gx1'):
            self._compute_one()
        return self._gx1

    @property
    def gx2(self):
        """:math:`g^x2`
        :type: int
        """
        if not hasattr(self, '_gx2'):
            self._compute_one()
        return self._gx2

    @property
    def zkp_x1(self):
        """Proof of knowledge of :math:`x1`
        """
        if not hasattr(self, '_zkp_x1'):
            self._compute_one()
        return self._zkp_x1

    @property
    def zkp_x2(self):
        """Proof of knowledge of :math:`x2`
        """
        if not hasattr(self, '_zkp_x2'):
            self._compute_one()
        return self._zkp_x2

    def one(self):
        return {
            'gx1': self.gx1,
            'zkp_x1': dict(self.zkp_x1),
            'gx2': self.gx2,
            'zkp_x2': dict(self.zkp_x2),
        }

    def process_one(
            self, data=None, *, verify=True,
            gx3=None, gx4=None, zkp_x3=None, zkp_x4=None):
        """Read in and verify the result of step one as sent by the other party

        Accepts either a dictionary of values in the form produced by ``one``
        or the required values passed in individually as keyword arguments.

        :param data: A dictionary containing the results of running step one at
            the other end of the connection.

            Should use the naming convention of the other party. ``data["x1"]``
            will be assigned to ``x3``, likewise for ``x2``, ``zkp_x1`` and
            ``zkp_x2``.

        :param gx3: :math:`g^x3`
        :param gx4: :math:`g^x4`
        :param zkp_x3: Proof that ``x3`` is known by the caller.
        :param zkp_x4: Proof that ``x4`` is known by the caller.

        :param verify: If ``False`` then ``zkp_x3`` and ``zkp_x4`` are ignored
            and proof verification is skipped.  This is a bad idea unless
            ``gx3`` and ``gx4`` have already been verified and is disallowed
            entirely if arguments are passed in a ``dict``

        :raises OutOfSequenceError: If called more than once.
        :raises InvalidProofError: If verification is enabled and either of
            the proofs fail
        """
        p = self.p
        g = self.g

        if not self.waiting_one:
            raise OutOfSequenceError("step one already processed")

        if data is not None:
            if any(param is not None for param in (gx3, gx4, zkp_x3, zkp_x4)):
                raise TypeError("unexpected keyword argument")

            if not verify:
                raise ValueError("dicts should always be verified")

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
            if zkp_x3 is None or zkp_x4 is None:
                raise Exception("expected zero knowledge proofs")
            self._verify_zkp(g, gx3, zkp_x3)
            self._verify_zkp(g, gx4, zkp_x4)

        self.gx3 = gx3
        self.gx4 = gx4

        self.waiting_one = False

    def _compute_two(self):
        if self.waiting_one:
            raise OutOfSequenceError(
                "can't compute step two without results from one"
            )

        if self.waiting_secret:
            raise OutOfSequenceError(
                "can't compute step two without secret"
            )

        p = self.p

        gx3 = self.gx3
        gx4 = self.gx4

        # A = g^((x1+x3+x4)*x2*s)
        #   = (g^x1*g^x3*g^x4)^(x2*s)
        t1 = (((self.gx1 * gx3) % p) * gx4) % p
        t2 = (self.x2 * self.secret) % p

        A = pow(t1, t2, p)

        # zero knowledge proof for ``x2*s``
        zkp_A = self._zkp(t1, t2, A)

        self._A = A
        self._zkp_A = MappingProxyType(zkp_A)

    @property
    def A(self):
        """:math:`g^((x3+x4+x1)*x2*s)`
        """
        if not hasattr(self, '_A'):
            self._compute_two()
        return self._A

    @property
    def zkp_A(self):
        """Proof of knowledge of :math:`x2*s`
        """
        if not hasattr(self, '_zkp_A'):
            self._compute_two()
        return self._zkp_A

    def two(self):
        return {
            'A': self.A,
            'zkp_A': dict(self.zkp_A),
        }

    def process_two(self, data=None, *, B=None, zkp_B=None, verify=True):
        """Read in and verify the result of performing step two on the other
        end of the connection.

        :param data: A dictionary containing the results of running step two at
            the other end of the connection.

            Should use the naming convention of the other party. ``B`` will be
            loaded from ``data["A"]`` and ``zkp_B`` will be loaded from
            ``data["zkp_A"]``.

        :param B: :math:`g^((x1+x2+x3)*x4*s)`

        :param zkp_B: Proof that :math:`x4*s` is known by the caller.

        :param verify: If ``False`` then ``zkp_B`` is ignored and proof
            verification is skipped.  This is a bad idea unless ``B`` has
            already been verified.

        :raises OutOfSequenceError: If called more than once or before
            ``process_one``.
        :raises InvalidProofError: If verification is enabled and either of
            the proofs fail
        """
        p = self.p

        if self.waiting_one:
            raise OutOfSequenceError("step two cannot be processed before one")

        if not self.waiting_two:
            raise OutOfSequenceError("step two already processed")

        if data is not None:
            if B is not None or zkp_B is not None:
                raise TypeError("unexpected keyword argument")
            B = data['A']
            zkp_B = data['zkp_A']

        if verify:
            generator = (((self.gx1*self.gx2) % p) * self.gx3) % p
            self._verify_zkp(generator, B, zkp_B)

        self.B = B

        self.waiting_two = False

    def _compute_three(self):
        if self.waiting_two:
            raise OutOfSequenceError(
                "can't compute step three without results from two"
            )

        p = self.p
        q = self.q

        # t3 = g^-(x4*x2*s)
        #    = (g^x4)^(x2*-s)
        bottom = pow(self.gx4, self.x2 * (q - self.secret), p)

        # t4 = B/(g^(x4*x2*s))
        #    = B*t3
        inner = (self.B * bottom) % p

        # K = (B/(g^(x4*x2*s)))^x2
        K = pow(inner, self.x2, p)

        # TODO Key derivation function is necessary to avoid exposing K but the
        # spec does not fix one and the choice of function depends on the
        # application.  Possibly choose one that can be adjusted to output a
        # key of approximately the same number of bits
        self._K = K

    @property
    def K(self):
        if not hasattr(self, '_K'):
            self._compute_three()
        return self._K


__all__ = ['NIST_80', 'NIST_112', 'NIST_128', 'JPAKE']
