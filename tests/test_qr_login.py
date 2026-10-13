"""Offline QR protocol fixtures: no real account, network, UI or credentials."""
from __future__ import annotations

from email.message import Message
import http.cookiejar
import io
import json
import socket
import ssl
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import patch

from baidu_netdisk.common import NetdiskError
from baidu_netdisk.qr_login import QrLoginClient, _MAX_BODY, _NoFollow, _json, _trusted


SIGN = "FAKE_QR_HANDLE_NOT_PUBLIC"
TEMPORARY = r"FAKE_TEMP_NOT_PUBLIC\escaped+&=?"
BDUSS = "FAKE_BDUSS_NOT_PUBLIC"
OLD_BDUSS = "FAKE_OLD_BDUSS_NOT_PUBLIC"
STOKEN = "FAKE_STOKEN_NOT_PUBLIC"
PNG = b"\x89PNG\r\n\x1a\n" + b"offline-image-fixture"
IMAGE_URL = "https://passport.baidu.com/v2/api/qrcode?sign=" + SIGN


class Response(io.BytesIO):
    """Supply the real urllib response methods used by CookieJar extraction."""
    def __init__(self, body=b"", *, cookies=(), location=None):
        super().__init__(body)
        self.headers = Message()
        for cookie in cookies:
            self.headers.add_header("Set-Cookie", cookie)
        if location is not None:
            self.headers.add_header("Location", location)
        self.read_limits = []

    def info(self):
        return self.headers

    def read(self, limit=-1):
        self.read_limits.append(limit)
        return super().read(limit)


class Opener:
    def __init__(self, *items):
        self.items = list(items)
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        if not self.items:
            raise AssertionError("Unexpected request: fixture queue is empty")
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def encoded(value):
    return json.dumps(value, ensure_ascii=True).encode("ascii")


def channel(status, value=None, *, jsonp=False):
    inner = {"status": status}
    if value is not None:
        inner["v"] = value
    payload = encoded({"errno": 0, "channel_v": json.dumps(inner)})
    return Response(b"(" + payload + b")" if jsonp else payload)


class QrLoginTests(unittest.TestCase):
    def make_client(self, *items, create_cookies=(), image=PNG, lifetime=300):
        opener = Opener(Response(encoded({"errno": 0, "sign": SIGN, "imgurl": IMAGE_URL}),
                                 cookies=create_cookies), Response(image), *items)
        client = QrLoginClient(opener=opener, lifetime=lifetime)
        self.assertEqual(client.create(), {"status": "waiting", "image": image})
        return client, opener

    def confirmed_client(self, *items, **kwargs):
        client, opener = self.make_client(channel(0, TEMPORARY, jsonp=True), *items, **kwargs)
        self.assertEqual(client.poll(), {"status": "confirmed"})
        return client, opener

    def assert_safe_error(self, code, action):
        with self.assertRaises(NetdiskError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        public = json.dumps(caught.exception.as_dict()) + str(caught.exception)
        for secret in (SIGN, TEMPORARY, BDUSS, OLD_BDUSS, STOKEN):
            self.assertNotIn(secret, public)
        return caught.exception

    def test_constructor_rejects_invalid_timeouts_and_lifetimes(self):
        for key, values in (("timeout", (True, False, None, "40", 0, 61, float("nan"), float("inf"))),
                            ("lifetime", (True, None, "300", 29, 601, float("nan"), float("inf")))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.assert_safe_error("invalid_timeout", lambda: QrLoginClient(**{key: value}))
        for timeout, lifetime in ((1, 30), (60, 600), (1.5, 30.5)):
            client = QrLoginClient(timeout=timeout, lifetime=lifetime, opener=Opener())
            self.assertEqual((client.timeout, client.lifetime), (timeout, lifetime))

    def test_create_returns_only_image_and_public_status_with_fixed_requests(self):
        create = Response(encoded({"errno": 0, "sign": SIGN, "imgurl": IMAGE_URL}))
        image = Response(PNG)
        opener = Opener(create, image)
        client = QrLoginClient(timeout=40, opener=opener)
        result = client.create()
        self.assertEqual(set(result), {"status", "image"})
        self.assertEqual(result["image"], PNG)
        self.assertNotIn(SIGN, repr(result))
        self.assertEqual(len(opener.requests), 2)
        request, timeout = opener.requests[0]
        parsed = urllib.parse.urlsplit(request.full_url)
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path),
                         ("https", "passport.baidu.com", "/v2/api/getqrcode"))
        self.assertEqual(urllib.parse.parse_qs(parsed.query),
                         {"lp": ["pc"], "qrloginfrom": ["pc"], "tpl": ["netdisk"], "apiver": ["v3"]})
        self.assertEqual(timeout, 40)
        self.assertEqual(create.read_limits, [_MAX_BODY + 1])
        self.assertEqual(image.read_limits, [_MAX_BODY + 1])
        self.assertTrue(create.closed and image.closed)

    def test_create_accepts_baidu_image_url_forms_and_supported_image_types(self):
        for image_url, image in (("//passport.baidu.com/v2/api/qrcode", PNG),
                                 ("passport.baidu.com/v2/api/qrcode/", b"GIF89a-fixture"),
                                 (IMAGE_URL, b"GIF87a-fixture"),
                                 (IMAGE_URL, b"\xff\xd8\xff-fixture")):
            with self.subTest(url=image_url):
                opener = Opener(Response(encoded({"errno": 0, "sign": SIGN, "imgurl": image_url})), Response(image))
                self.assertEqual(QrLoginClient(opener=opener).create()["image"], image)
                self.assertTrue(opener.requests[1][0].full_url.startswith("https://passport.baidu.com/"))

    def test_untrusted_urls_are_rejected_before_network_or_cookie_release(self):
        urls = ("http://passport.baidu.com/v2/api/qrcode", "https://evil.example/v2/api/qrcode",
                "https://passport.baidu.com.evil.example/v2/api/qrcode",
                "https://passport.baidu.com:444/v2/api/qrcode", "https://user:pass@passport.baidu.com/v2/api/qrcode",
                "https://passport.baidu.com/v2/api/qrcode#fragment", "https://passport.baidu.com/other",
                "https://passport.baidu.com/v2/api/../qrcode", "https://passport.baidu.com:invalid/v2/api/qrcode")
        for url in urls:
            with self.subTest(url=url):
                opener = Opener(Response(encoded({"errno": 0, "sign": SIGN, "imgurl": url})))
                self.assert_safe_error("qr_untrusted_url", QrLoginClient(opener=opener).create)
                self.assertEqual(len(opener.requests), 1)
        self.assert_safe_error("qr_untrusted_url", lambda: _trusted(None, {"/channel/unicast"}))

    def test_create_rejects_api_errors_missing_handles_and_malformed_json(self):
        bad_data = ({"errno": 1, "sign": SIGN}, {"errno": True}, {"errno": "0"},
                    {"errno": 0}, {"errno": 0, "sign": "", "imgurl": IMAGE_URL},
                    {"errno": 0, "sign": SIGN + "\n", "imgurl": IMAGE_URL},
                    {"errno": 0, "sign": "x" * 1025, "imgurl": IMAGE_URL},
                    {"errno": 0, "sign": SIGN, "imgurl": None})
        for data in bad_data:
            with self.subTest(data=data):
                expected = "qr_creation_failed" if type(data.get("errno")) is not int or data["errno"] else "qr_invalid_response"
                opener = Opener(Response(encoded(data)))
                self.assert_safe_error(expected, QrLoginClient(opener=opener).create)
                self.assertEqual(len(opener.requests), 1)
        for raw in (b"[]", b"null", b"not-json", b"\xff", b'callback({"errno":0})', b'({"errno":0});'):
            with self.subTest(raw=raw):
                self.assert_safe_error("qr_invalid_response", lambda: _json(raw))

    def test_image_and_response_size_limits_reject_payloads_without_secret_echo(self):
        client = QrLoginClient(opener=Opener(Response(b"x" * (_MAX_BODY + 1))))
        self.assert_safe_error("qr_invalid_response", client.create)
        for image in (b"", b"<html>" + TEMPORARY.encode() + b"</html>", b"x" * (_MAX_BODY + 1)):
            with self.subTest(size=len(image)):
                opener = Opener(Response(encoded({"errno": 0, "sign": SIGN, "imgurl": IMAGE_URL})), Response(image))
                expected = "qr_invalid_response" if len(image) > _MAX_BODY else "qr_invalid_image"
                self.assert_safe_error(expected, QrLoginClient(opener=opener).create)

    def test_jsonp_nested_channel_preserves_escaped_credential_in_local_exchange(self):
        exchange = Response(cookies=(f"BDUSS={BDUSS}; Domain=.baidu.com; Path=/; Secure",))
        client, opener = self.confirmed_client(exchange)
        self.assertEqual(client.poll(), {"status": "confirmed"})
        self.assertEqual(len(opener.requests), 3)
        cookie = client.exchange()
        self.assertEqual(cookie, f"BDUSS={BDUSS}")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(opener.requests[-1][0].full_url).query)
        self.assertEqual(query["bduss"], [TEMPORARY])
        self.assertEqual(query["u"], ["https%3A%2F%2Fpan.baidu.com%2Fdisk%2Fmain"])
        self.assertEqual(query["loginVersion"], ["v4"])
        self.assertEqual(urllib.parse.urlsplit(opener.requests[-1][0].full_url).path, "/v3/login/main/qrbdusslogin")
        self.assertIsNone(client._temporary)

    def test_waiting_responses_and_poll_requests_have_exact_public_state(self):
        client, opener = self.make_client(*(Response(encoded(data)) for data in
            ({"errno": 1}, {"errno": 1, "channel_v": ""}, {"errno": 0}, {"errno": 0, "channel_v": ""})))
        for unused in range(4):
            self.assertEqual(client.poll(), {"status": "waiting"})
        request = opener.requests[-1][0]
        parsed = urllib.parse.urlsplit(request.full_url)
        self.assertEqual(parsed.path, "/channel/unicast")
        self.assertEqual(parsed.netloc, "passport.baidu.com")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self.assertEqual(query["channel_id"], [SIGN])
        self.assertEqual(query["callback"], [""])
        self.assertEqual(query["tpl"], ["netdisk"])

    def test_scanned_and_cancelled_are_distinct_and_cancellation_is_terminal(self):
        client, opener = self.make_client(channel(1), channel(2, TEMPORARY))
        self.assertEqual(client.poll(), {"status": "scanned"})
        self.assertEqual(client.poll(), {"status": "cancelled"})
        self.assertEqual(client.poll(), {"status": "cancelled"})
        self.assertEqual(len(opener.requests), 4)
        self.assert_safe_error("qr_not_confirmed", client.exchange)
        self.assertIsNone(client._temporary)

    def test_poll_rejects_malformed_states_credentials_and_error_codes(self):
        bad = (({}, "qr_invalid_response"), ({"errno": True}, "qr_invalid_response"),
               ({"errno": "0"}, "qr_invalid_response"), ({"errno": 2, "channel_v": TEMPORARY}, "qr_poll_failed"),
               ({"errno": 1, "channel_v": TEMPORARY}, "qr_poll_failed"),
               ({"errno": 0, "channel_v": "invalid"}, "qr_invalid_response"),
               ({"errno": 0, "channel_v": [1]}, "qr_invalid_response"))
        bad_channels = ({"status": True}, {"status": "0"}, {"status": 7, "v": TEMPORARY},
                        {"status": 0}, {"status": 0, "v": ""}, {"status": 0, "v": 1},
                        {"status": 0, "v": "x" * 8193}, {"status": 0, "v": TEMPORARY + "\n"},
                        {"status": 0, "v": "\u0080"})
        bad += tuple(({"errno": 0, "channel_v": item}, "qr_invalid_response") for item in bad_channels)
        for data, expected in bad:
            with self.subTest(data=data):
                client, opener = self.make_client(Response(encoded(data)))
                self.assert_safe_error(expected, client.poll)
                self.assertIsNone(client._temporary)

    def test_only_poll_timeouts_remain_waiting_and_dns_ssl_errors_fail_safely(self):
        for error in (TimeoutError(TEMPORARY), urllib.error.URLError(TimeoutError(TEMPORARY))):
            with self.subTest(error=type(error).__name__):
                client, opener = self.make_client(error)
                self.assertEqual(client.poll(), {"status": "waiting", "network_pending": True})
                self.assert_safe_error("qr_request_timeout", QrLoginClient(opener=Opener(error)).create)
        for error in (urllib.error.URLError(socket.gaierror(TEMPORARY)), urllib.error.URLError(ssl.SSLError(TEMPORARY)),
                      ssl.SSLError(TEMPORARY), OSError(TEMPORARY)):
            with self.subTest(error=type(error).__name__):
                client, opener = self.make_client(error)
                self.assert_safe_error("qr_network_error", client.poll)

    def test_http_errors_are_sanitized_and_creation_cannot_follow_redirects(self):
        for status in (302, 401, 403, 500):
            headers = Message()
            headers.add_header("Location", "https://evil.example/" + TEMPORARY)
            error = urllib.error.HTTPError(IMAGE_URL, status, TEMPORARY, headers, io.BytesIO(BDUSS.encode()))
            with self.subTest(status=status):
                failure = self.assert_safe_error("qr_http_error", QrLoginClient(opener=Opener(error)).create)
                self.assertEqual(failure.details, {"status": status})
        self.assertIsNone(_NoFollow().redirect_request(urllib.request.Request(IMAGE_URL), None, 302,
                          "Found", Message(), "https://evil.example/" + TEMPORARY))

    def test_expiration_and_not_started_use_no_network_and_clear_temporary_state(self):
        client = QrLoginClient(opener=Opener())
        self.assert_safe_error("qr_not_started", client.poll)
        self.assert_safe_error("qr_not_confirmed", client.exchange)
        with patch("baidu_netdisk.qr_login.time.monotonic", return_value=100):
            client, opener = self.confirmed_client(lifetime=30)
        with patch("baidu_netdisk.qr_login.time.monotonic", return_value=130):
            self.assertEqual(client.poll(), {"status": "expired"})
            self.assertEqual(client.poll(), {"status": "expired"})
            self.assert_safe_error("qr_not_confirmed", client.exchange)
        self.assertEqual(len(opener.requests), 3)
        self.assertIsNone(client._temporary)

    def test_exchange_returns_cookiejar_scoped_cookies_and_never_replays(self):
        response = Response(cookies=(f"BDUSS={BDUSS}; Domain=.baidu.com; Path=/; Secure; HttpOnly",
                                    f"STOKEN={STOKEN}; Domain=.baidu.com; Path=/; Secure",
                                    "BAIDUID=fake-id; Domain=.baidu.com; Path=/",
                                    "PASSPORT_ONLY=must-not-send; Path=/; Secure",
                                    "WRONG_PATH=must-not-send; Domain=.baidu.com; Path=/passport",
                                    "EXPIRED=must-not-send; Domain=.baidu.com; Path=/; Max-Age=0"))
        client, opener = self.confirmed_client(response)
        cookie = client.exchange()
        fields = dict(part.strip().split("=", 1) for part in cookie.split(";"))
        self.assertEqual(fields, {"BDUSS": BDUSS, "STOKEN": STOKEN, "BAIDUID": "fake-id"})
        self.assertIsNone(client._temporary)
        self.assert_safe_error("qr_not_confirmed", client.exchange)
        self.assertEqual(len(opener.requests), 4)

    def test_exchange_reads_redirect_cookies_without_requesting_location(self):
        headers = Message()
        headers.add_header("Set-Cookie", f"BDUSS={BDUSS}; Domain=.baidu.com; Path=/; Secure")
        headers.add_header("Location", "https://evil.example/" + TEMPORARY)
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                error = urllib.error.HTTPError("https://passport.baidu.com/v3/login/main/qrbdusslogin", status,
                                               "Found", headers, io.BytesIO())
                client, opener = self.confirmed_client(error)
                self.assertEqual(client.exchange(), f"BDUSS={BDUSS}")
                self.assertEqual(len(opener.requests), 4)
                self.assertTrue(all(urllib.parse.urlsplit(request.full_url).hostname == "passport.baidu.com"
                                    for request, timeout in opener.requests))

    def test_exchange_failure_and_expiry_consume_temporary_credential(self):
        for item in (Response(), Response(cookies=("BDUSS=; Domain=.baidu.com; Path=/",)),
                     TimeoutError(TEMPORARY), urllib.error.URLError(socket.gaierror(TEMPORARY)),
                     Response(b"x" * (_MAX_BODY + 1))):
            with self.subTest(item=type(item).__name__):
                client, opener = self.confirmed_client(item)
                expected = "qr_exchange_failed" if isinstance(item, Response) and len(item.getvalue()) <= _MAX_BODY else (
                    "qr_invalid_response" if isinstance(item, Response) else "qr_request_timeout" if isinstance(item, TimeoutError)
                    else "qr_network_error")
                self.assert_safe_error(expected, client.exchange)
                self.assertIsNone(client._temporary)
                self.assert_safe_error("qr_not_confirmed", client.exchange)
                self.assertEqual(len(opener.requests), 4)
        with patch("baidu_netdisk.qr_login.time.monotonic", return_value=100):
            client, opener = self.confirmed_client(lifetime=30)
        with patch("baidu_netdisk.qr_login.time.monotonic", return_value=130):
            self.assert_safe_error("qr_expired", client.exchange)
        self.assertIsNone(client._temporary)
        self.assertEqual(len(opener.requests), 3)

    def test_exchange_requires_new_bduss_that_is_actually_usable_by_netdisk(self):
        old_cookie = f"BDUSS={OLD_BDUSS}; Domain=.baidu.com; Path=/; Secure"
        for new_cookie in (None, f"BDUSS={BDUSS}; Domain=evil.example; Path=/; Secure",
                           f"BDUSS={BDUSS}; Path=/; Secure",
                           f"BDUSS={BDUSS}; Domain=.baidu.com; Path=/v3/login/main/; Secure"):
            with self.subTest(scope=new_cookie):
                client, opener = self.confirmed_client(Response(cookies=() if new_cookie is None else (new_cookie,)),
                                                       create_cookies=(old_cookie,))
                self.assert_safe_error("qr_exchange_failed", client.exchange)
                self.assertIsNone(client._temporary)
                self.assert_safe_error("qr_not_confirmed", client.exchange)

    def test_missing_response_object_and_malformed_headers_fail_without_secret_echo(self):
        self.assert_safe_error("qr_invalid_response", QrLoginClient(opener=Opener(None)).create)
        client, opener = self.confirmed_client(Response(cookies=("BDUSS", "not-a-cookie", "BDUSS=; Path=/")))
        self.assert_safe_error("qr_exchange_failed", client.exchange)


if __name__ == "__main__":
    unittest.main()
