"""Experimental miothealth client, independently implemented from Mi Fitness wire facts.

Source: Mi Fitness 3.59.2i CloudInterceptor, nl4/rk4, XMPassport.
No account password or HTTP payload is logged. Only Xiaomi HTTPS endpoints are allowed.
"""

import base64
import hashlib
import http.cookiejar
from http.cookiejar import Cookie
import json
import os
import pathlib
import secrets
import stat
import struct
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4


class BindError(Exception):
    """Safe, non-secret error suitable for console output."""


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(value):
    if not isinstance(value, str):
        raise BindError('Missing Base64 field.')
    try:
        return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except ValueError:
        raise BindError('Invalid Base64 field.') from None


def text_field(obj, name):
    value = obj.get(name)
    if not isinstance(value, str) or not value or any(c in value for c in '\r\n'):
        raise BindError(f'Missing or invalid field: {name}')
    return value


class RC4:
    """RC4-drop1024; continue the same cipher across encrypted form fields."""

    def __init__(self, key):
        if not key:
            raise BindError('Empty RC4 key.')
        self.cipher = Cipher(ARC4(key), mode=None).encryptor()
        self.cipher.update(bytes(1024))

    def crypt(self, data):
        return self.cipher.update(data)


def signature(method, path, params, security):
    parts = [method.upper(), path] if method else []
    parts += [f'{k}={params[k]}' for k in sorted(params)]
    return b64(hashlib.sha1('&'.join(parts + [security]).encode()).digest())


def encrypted_form(path, data, security, nonce=None):
    nonce = nonce or secrets.token_bytes(8) + struct.pack('>I', int(time.time() / 60))
    if len(nonce) != 12:
        raise BindError('Nonce must contain 12 bytes.')
    key = hashlib.sha256(unb64(security) + nonce).digest()
    signed_nonce = b64(key)
    params = {'data': json.dumps(data, separators=(',', ':'), ensure_ascii=False)}
    params['rc4_hash__'] = signature('POST', path, params, signed_nonce)
    cipher = RC4(key)
    encrypted = {k: b64(cipher.crypt(params[k].encode())) for k in sorted(params)}
    encrypted['signature'] = signature('POST', path, encrypted, signed_nonce)
    encrypted['_nonce'] = b64(nonce)
    return encrypted, key


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ''
    if (parsed.scheme != 'https' or parsed.username or parsed.password
            or parsed.port not in (None, 443)
            or not (host == 'xiaomi.com' or host.endswith('.xiaomi.com')
                    or host == 'mi.com' or host.endswith('.mi.com'))):
        raise BindError('Refusing a URL outside Xiaomi HTTPS services.')
    return url


class XiaomiRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed_url(newurl)
        # Health requests contain explicit cookies; never follow their redirects.
        if getattr(req, '_no_redirect', False):
            raise BindError('Health service redirected; log in again.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class XiaomiRequest(urllib.request.Request):
    _no_redirect = False


class HTTP:
    def __init__(self):
        self.extension_pragma = None
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies), XiaomiRedirect())

    def request(self, url, data=None, headers=None, timeout=30):
        self.extension_pragma = None
        request = XiaomiRequest(allowed_url(url), data=data, headers=headers or {})
        request._no_redirect = bool(headers and 'Cookie' in headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                self.extension_pragma = response.headers.get('Extension-Pragma')
                body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise BindError('HTTP response exceeded size limit.')
            return body
        except urllib.error.HTTPError as exc:
            raise BindError(f'Xiaomi HTTP status {exc.code}.') from None
        except (urllib.error.URLError, TimeoutError):
            raise BindError('Xiaomi request failed or timed out.') from None


def json_object(raw):
    try:
        obj = json.loads(raw.decode().removeprefix('&&&START&&&'))
    except (ValueError, UnicodeError):
        raise BindError('Invalid JSON response.') from None
    if not isinstance(obj, dict):
        raise BindError('Expected a JSON object.')
    return obj


def private_write(path, data):
    """Atomically replace a private state file, never following a target symlink."""
    path = pathlib.Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
        raise BindError('State directory must be private (mode 700).')
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise BindError('State file must be owned by you with mode 600.')
        return json_object(stream.read(100_000))


def login_security(response, extension_pragma=None):
    """SDK login fields may live in Extension-Pragma instead of the JSON body."""
    status = response.get('securityStatus', 0)
    if type(status) is not int:
        raise BindError('Invalid login security status.')
    if status != 0 or response.get('notificationUrl'):
        raise BindError(f'Xiaomi requires additional account verification (securityStatus={status}).')
    fields = response
    if not response.get('ssecurity') and extension_pragma:
        fields = json_object(extension_pragma.encode())
    if not fields.get('ssecurity'):
        raise BindError('Login returned no session key; securityStatus=0, '
                        f'Extension-Pragma present={bool(extension_pragma)}. '
                        'No password retry was made.')
    security = text_field(fields, 'ssecurity')
    nonce = fields.get('nonce')
    if isinstance(nonce, str) and nonce.isascii() and nonce.isdecimal():
        nonce = int(nonce)
    if type(nonce) is not int:
        raise BindError('Missing STS nonce.')
    return security, nonce


def password_login(http, user, password, phone_id):
    """One password attempt; captcha/2FA stops instead of retrying automatically."""
    ua = 'Android-14-3.59.2i-Linux-MiBandProbe'
    headers = {'User-Agent': ua}
    http.cookies.set_cookie(Cookie(
        0, 'deviceId', phone_id, None, False, 'account.xiaomi.com', False, False,
        '/', True, True, None, True, None, None, {}, False))
    query = urllib.parse.urlencode({'sid': 'miothealth', '_json': 'true'})
    meta = json_object(http.request('https://account.xiaomi.com/pass/serviceLogin?' + query, headers=headers))
    form = {k: text_field(meta, k) for k in ('_sign', 'qs', 'callback')}
    form.update(user=user, hash=hashlib.md5(password.encode()).hexdigest().upper(),
                sid='miothealth', _json='true')
    response = json_object(http.request('https://account.xiaomi.com/pass/serviceLoginAuth2',
                                        urllib.parse.urlencode(form).encode(), headers))
    return complete_login(http, response, phone_id)


def complete_login(http, response, phone_id):
    """Consume either a password or browser-poll response and exchange the STS token."""
    headers = {'User-Agent': 'Android-14-3.59.2i-Linux-MiBandProbe'}
    if response.get('code') != 0:
        code = response.get('code')
        safe_code = code if isinstance(code, int) else 'unknown'
        raise BindError(f'Login rejected (code {safe_code}); captcha/2FA may require browser login.')
    security, nonce = login_security(response, getattr(http, 'extension_pragma', None))
    location = allowed_url(text_field(response, 'location'))
    client_sign = signature(None, None, {'nonce': str(nonce)}, security)
    parts = urllib.parse.urlsplit(location)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query += [('clientSign', client_sign), ('_userIdNeedEncrypt', 'true')]
    callback = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
    http.request(callback, headers=headers)
    # CookieJar keeps the token private; select only cookies for this service's host.
    host = urllib.parse.urlsplit(location).hostname
    tokens = [c.value for c in http.cookies if c.name in ('miothealth_serviceToken', 'serviceToken')
              and (host == c.domain.lstrip('.') or host.endswith('.' + c.domain.lstrip('.')))]
    if not tokens:
        raise BindError('Login callback did not supply a service token.')
    account = dict(response)
    for cookie in http.cookies:
        if cookie.name in ('cUserId', 'userId') and cookie.domain.lstrip('.') == 'account.xiaomi.com':
            account.setdefault(cookie.name, cookie.value)
    return {'user_id': str(account['userId']), 'c_user_id': text_field(account, 'cUserId'),
            'service_token': tokens[-1], 'security': security, 'phone_id': phone_id}


def browser_login(http, phone_id, present):
    """XMPassport getQRLoginUrl/loginByLongPolling, with login in a normal browser."""
    result = json_object(http.request('https://account.xiaomi.com/longPolling/loginUrl?sid=miothealth'))
    if result.get('code') != 0:
        raise BindError('Xiaomi could not start browser login.')
    login_url = allowed_url(text_field(result, 'loginUrl'))
    poll_url = allowed_url(text_field(result, 'lp'))
    # Validate every returned endpoint before opening a browser or starting the poll.
    present(login_url)
    response = json_object(http.request(poll_url, timeout=300))
    return complete_login(http, response, phone_id)


class HealthClient:
    def __init__(self, session, region, http=None):
        if region not in ('cn', 'de', 'us', 'sg', 'in', 'ru'):
            raise BindError('Unsupported service region.')
        self.session, self.region = session, region
        self.http = http or HTTP()
        self.host = ('' if region == 'cn' else region + '.') + 'hlth.io.mi.com'

    def post(self, operation, data):
        if operation not in ('hello', 'ecdh', 'bind', 'devices'):
            raise BindError('Unsupported account operation.')
        path = '/app/v1/source/get_source_list' if operation == 'devices' else '/bind/' + operation
        url_path = path if operation == 'devices' else '/healthapp' + path
        form, key = encrypted_form(path, data, text_field(self.session, 'security'))
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'region_tag': self.region,
                   'locale': 'en_US', 'HandleParams': 'true',
                   'Cookie': 'cUserId=' + text_field(self.session, 'c_user_id')
                             + '; serviceToken=' + text_field(self.session, 'service_token'),
                   'User-Agent': 'Android-14-3.59.2i-Linux-MiBandProbe-'
                                 + hashlib.md5(self.session['phone_id'].encode()).hexdigest() + '-'
                                 + hashlib.md5(self.session['user_id'].encode()).hexdigest()}
        suffix = '?locale=en_US' if operation == 'bind' else ''
        raw = self.http.request('https://' + self.host + url_path + suffix,
                                urllib.parse.urlencode(form).encode(), headers)
        if raw.lstrip().startswith(b'{'):
            # Only errors may bypass encryption; plaintext success is never trusted.
            error = json_object(raw)
            code = error.get('code')
            safe_code = code if isinstance(code, int) else 'unknown'
            raise BindError(f'Unencrypted health response (code {safe_code}); session may have expired.')
        result = json_object(RC4(key).crypt(unb64(raw.decode('ascii'))))
        if result.get('code', result.get('status', result.get('alternate'))) not in (0, 200) or not isinstance(result.get('result'), dict):
            raise BindError('Health API rejected request or returned an invalid envelope.')
        return result['result']
