import unittest

from sympy.ntheory.primetest import isprime

import jpake.parameters


class BaseParameterTestsMixin(object):
    parameters = None

    def test_p_is_prime(self):
        # TODO :func:`sympy.ntheory.primetest.isprime` is probabilistic for
        # values of the size we are checking
        self.assertTrue(isprime(self.parameters.p))

    def test_q_is_prime(self):
        # TODO :func:`sympy.ntheory.primetest.isprime` is probabilistic for
        # values of the size we are checking
        self.assertTrue(isprime(self.parameters.q))


class Nist80ParametersTestCase(BaseParameterTestsMixin, unittest.TestCase):
    parameters = jpake.parameters.NIST_80


class Nist112ParametersTestCase(BaseParameterTestsMixin, unittest.TestCase):
    parameters = jpake.parameters.NIST_112


class Nist128ParametersTestCase(BaseParameterTestsMixin, unittest.TestCase):
    parameters = jpake.parameters.NIST_128
