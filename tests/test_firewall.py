import unittest
from firewall import is_blacklisted

class TestFirewall(unittest.TestCase):
    def test_blacklisted_ip(self):
        self.assertTrue(is_blacklisted("192.168.1.10"))

    def test_non_blacklisted_ip(self):
        self.assertFalse(is_blacklisted("8.8.8.8"))

if __name__ == "__main__":
    unittest.main()
