import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from server import create_server


class NewtonSecurityLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_refuses_non_localhost_bind(self) -> None:
        with self.assertRaises(ValueError):
            create_server("0.0.0.0", 0)

    def test_main_dashboard_serves_security_headers(self) -> None:
        with urlopen(f"{self.base_url}/") as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertIn("object-src 'none'", resp.headers.get("Content-Security-Policy", ""))

    def test_idor_vulnerable_vs_secure(self) -> None:
        with urlopen(f"{self.base_url}/api/student/attendance?student_id=STU-1099&mode=vulnerable") as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(resp.status, 200)
            self.assertTrue(data["idor_exposed"])

        with self.assertRaises(HTTPError) as ctx:
            urlopen(f"{self.base_url}/api/student/attendance?student_id=STU-1099&mode=secure")
        self.assertEqual(ctx.exception.code, 403)

    def test_xss_preview_vulnerable_vs_secure(self) -> None:
        payload = "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
        with urlopen(f"{self.base_url}/lab/xss-preview?q={payload}&mode=vulnerable") as resp:
            body = resp.read().decode("utf-8")
            self.assertIn("<img src=x onerror=alert(1)>", body)

        with urlopen(f"{self.base_url}/lab/xss-preview?q={payload}&mode=secure") as resp:
            body = resp.read().decode("utf-8")
            self.assertIn("&lt;img src=x onerror=alert(1)&gt;", body)
            self.assertIn("script-src 'none'", resp.headers.get("Content-Security-Policy", ""))

    def test_scan_and_markdown_report(self) -> None:
        req = Request(
            f"{self.base_url}/api/scan",
            data=json.dumps({"mode": "vulnerable"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(len(data["checks"]), 6)
            self.assertTrue(len(data["findings"]) >= 6)

        with urlopen(f"{self.base_url}/api/report?mode=secure&format=markdown") as resp:
            md = resp.read().decode("utf-8")
            self.assertIn("Newton Dashboard Security Research Lab", md)
            self.assertIn("Remediated", md)


if __name__ == "__main__":
    unittest.main()
