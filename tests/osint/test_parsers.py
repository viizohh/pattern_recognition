"""Unit tests for OSINT parsers"""

import unittest
from net_watch.osint.parsers.emails import EmailParser
from net_watch.osint.parsers.phones import PhoneParser
from net_watch.osint.parsers.entities import EntityParser
from net_watch.osint.utils import normalize_domain, is_valid_email


class TestEmailParser(unittest.TestCase):
    """Test email extraction and validation"""

    def setUp(self):
        self.parser = EmailParser()

    def test_extract_from_text(self):
        """Test email extraction from plain text"""
        text = "Contact us at admin@testdomain.com or support@anotherdomain.org"
        emails = self.parser.extract_from_text(text)

        self.assertIn('admin@testdomain.com', emails)
        self.assertIn('support@anotherdomain.org', emails)
        self.assertEqual(len(emails), 2)

    def test_extract_from_html(self):
        """Test email extraction from HTML"""
        html = '<a href="mailto:info@testdomain.com">Email us</a> or write to contact@testdomain.com'
        emails = self.parser.extract_from_html(html)

        self.assertIn('info@testdomain.com', emails)
        self.assertIn('contact@testdomain.com', emails)

    def test_exclude_false_positives(self):
        """Test that false positives are excluded"""
        text = "test@testdomain.com and fake@localhost"
        emails = self.parser.extract_from_text(text)

        self.assertIn('test@testdomain.com', emails)
        self.assertNotIn('fake@localhost', emails)  # Should be excluded

    def test_group_by_domain(self):
        """Test grouping emails by domain"""
        emails = {
            'admin@testdomain.com',
            'info@testdomain.com',
            'contact@otherdomain.org'
        }

        grouped = self.parser.group_by_domain(emails)

        self.assertIn('testdomain.com', grouped)
        self.assertEqual(len(grouped['testdomain.com']), 2)
        self.assertIn('otherdomain.org', grouped)


class TestPhoneParser(unittest.TestCase):
    """Test phone number extraction"""

    def setUp(self):
        self.parser = PhoneParser()

    def test_extract_us_format(self):
        """Test US phone format extraction"""
        text = "Call us at (555) 123-4567 or 555.987.6543"
        phones = self.parser.extract_from_text(text)

        self.assertTrue(len(phones) >= 2)

    def test_extract_international_format(self):
        """Test international phone format extraction"""
        text = "International: +1-555-123-4567"
        phones = self.parser.extract_from_text(text)

        self.assertTrue(len(phones) >= 1)

    def test_normalize_phone(self):
        """Test phone normalization"""
        phone = "(555) 123-4567"
        normalized = self.parser.normalize_phone(phone)

        self.assertTrue('+' in normalized)
        self.assertTrue('555' in normalized)


class TestEntityParser(unittest.TestCase):
    """Test name and organization extraction"""

    def setUp(self):
        self.parser = EntityParser()

    def test_extract_name_with_title(self):
        """Test name extraction with title"""
        text = "Contact Dr. John Smith for more information."
        names = self.parser.extract_names(text)

        self.assertTrue(len(names) > 0)
        self.assertTrue(any('John' in name and 'Smith' in name for name in names))

    def test_extract_organization(self):
        """Test organization extraction"""
        text = "© 2024 Acme Corporation. All rights reserved."
        orgs = self.parser.extract_organizations(text)

        self.assertTrue(len(orgs) > 0)
        self.assertTrue(any('Acme' in org for org in orgs))

    def test_extract_organization_with_indicator(self):
        """Test org extraction with indicator"""
        text = "Example Technologies Inc is a leading company."
        orgs = self.parser.extract_organizations(text)

        self.assertTrue(len(orgs) > 0)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions"""

    def test_normalize_domain_with_scheme(self):
        """Test domain normalization with http/https"""
        result = normalize_domain('https://www.Example.com')
        self.assertEqual(result, 'example.com')

    def test_normalize_domain_with_path(self):
        """Test domain normalization with path"""
        result = normalize_domain('example.com/contact')
        self.assertEqual(result, 'example.com')

    def test_normalize_domain_uppercase(self):
        """Test domain normalization converts to lowercase"""
        result = normalize_domain('EXAMPLE.COM')
        self.assertEqual(result, 'example.com')

    def test_normalize_domain_reject_ip(self):
        """Test that IP addresses are rejected"""
        result = normalize_domain('192.168.1.1')
        self.assertIsNone(result)

    def test_is_valid_email_valid(self):
        """Test valid email validation"""
        self.assertTrue(is_valid_email('admin@example.com'))
        self.assertTrue(is_valid_email('user.name+tag@example.co.uk'))

    def test_is_valid_email_invalid(self):
        """Test invalid email validation"""
        self.assertFalse(is_valid_email('notanemail'))
        self.assertFalse(is_valid_email('@example.com'))
        self.assertFalse(is_valid_email('user@'))


if __name__ == '__main__':
    unittest.main()
