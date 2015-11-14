import unittest

from jpake.tests import test_jpake
from jpake.tests import test_parameters

loader = unittest.TestLoader()
suite = unittest.TestSuite((
    loader.loadTestsFromModule(test_jpake),
    loader.loadTestsFromModule(test_parameters),
))
