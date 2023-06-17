import requests
import unittest
from unittest import TestCase, mock

class HTTPTest(TestCase):

    def test_http_request(self):

        url = "http://example.com"

        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.text = "Tester Mock Response and I am a Teapod, How are you today"

        with mock.patch("requests.get", return_value=mock_response):
            response = requests.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Tester Mock Response and I am a Teapod, How are you today")

if __name__ == '__main__':
    unittest.main() 

