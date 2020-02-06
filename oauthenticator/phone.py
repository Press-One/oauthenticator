"""phone + verification code login module"""
import redis

from traitlets import Integer, Unicode, Set

from jupyterhub.auth import Authenticator
from jupyterhub.handlers.login import LoginHandler


class PhoneLoginHandler(LoginHandler):
    """Render the login page."""
    pass


class PhoneAuthenticator(Authenticator):
    login_service = 'phone'

    whitelist = Set(
        config=True,
        help="whitelist of phone number, allow login without phone code",
    )
    # for redis server
    redis_host = Unicode(
        '127.0.0.1',
        help="""redis server ip""",
    ).tag(config=True)

    redis_port = Integer(
        6379,
        help="""redis port""",
    ).tag(config=True)

    redis_db = Integer(
        0,
        help="""redis database""",
    ).tag(config=True)

    def get_handlers(self, app):
        handlers = [
            (r'/login', PhoneLoginHandler),
        ]
        return handlers


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.redis = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            db=self.redis_db
        )

    def format_phone(self, phone):
        if not phone:
            return phone

        if phone and phone[0] != '+' and len(phone) == 11:
            phone = f'+86{phone}'
        if phone[0] == '+':
            phone = phone[1:]
        return phone

    def get_redis_key(self, site, phone):
        phone = self.format_phone(phone)
        prefix = 'jupyterhub:phone:code:'
        key = f'{prefix}:{site}:{phone}'
        return key

    def delete_code_from_redis(self, site, phone):
        key = self.get_redis_key(site, phone)
        return self.redis.delete(key)

    def get_code_from_redis(self, site, phone):
        key = self.get_redis_key(site, phone)
        val = self.redis.get(key)
        if isinstance(val, bytes):
            val = val.decode()
        return val

    def is_valid_code(self, site, phone, code):
        return code and self.get_code_from_redis(site, phone) == code

    def login_success(self, site, phone):
        self.delete_code_from_redis(site, phone)

    async def authenticate(self, handler, data):
        phone = self.format_phone(data['phone'].strip())  # phone number
        code = data['code'].strip()    # verification code
        site = 'xue-cn'  # FIXME: hardcode
        auth = {
            'name': phone,
            'auth_state': {
                'phone_user': {
                    'avatar_url': None,
                    'name': phone,
                    'login': '',
                }
            },
            'admin': False,
        }

        if phone in self.whitelist:  # for appstore review
            return auth
        elif self.is_valid_code(site, phone, code):
            self.login_success(site, phone)
            return auth
        else:
            self.log.info(f'Invalid code = {code} by phone = {phone} site = {site}')
