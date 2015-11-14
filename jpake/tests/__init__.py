import unittest

from jpake.tests import test_jpake

loader = unittest.TestLoader()
suite = unittest.TestSuite((
    loader.loadTestsFromModule(test_jpake),
))
