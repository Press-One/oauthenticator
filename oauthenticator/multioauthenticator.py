from tornado import gen
from tornado.escape import url_escape
from tornado.httputil import url_concat

from traitlets import (
    Unicode, Type, List, Tuple
)

from jupyterhub.auth import Authenticator
from jupyterhub.handlers.login import LoginHandler, LogoutHandler
from jupyterhub.user import User
from jupyterhub.utils import url_path_join

from .google import GoogleOAuthenticator, GoogleLoginHandler, GoogleOAuthHandler
from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator


class MultiLoginHandler(LoginHandler):

    def _render(self, login_error=None, username=None):
        """
        Mainly changes the template, also simplify a bit
        """
        self.statsd.incr('login.request')

        nextval = self.get_argument('next', default='/hub')
        inviter = self.get_argument('inviter', default='')
        login_url_query = {'next': nextval}
        if inviter:
            login_url_query['inviter'] = inviter

        oauth_list = []
        for auth_info in self.authenticator._auth_provider_list:
            auth_class = auth_info[0]
            auth_obj = auth_class(config=self.config)
            login_service = auth_obj.login_service
            authenticator_login_url = url_concat(
                self.authenticator.login_url(self.hub.base_url, login_service),
                login_url_query
            )
            oauth_list.append({
                'login_service': login_service,
                'authenticator_login_url': authenticator_login_url,
            })

        return self.render_template(
            'login.html',
            oauth_list=oauth_list,
            next=url_escape(nextval),
            username=username,
            login_error=login_error,
            custom_html=self.authenticator.custom_html,
        )

    @gen.coroutine
    def get(self):
        """
        Simplify rendering as there is no username
        """
        if hasattr(self, 'current_user'):
            user = self.current_user
        else:
            user = self.get_current_user()
        if isinstance(user, User):
            # set new login cookie
            # because single-user cookie may have been cleared or incorrect
            self.set_login_cookie(self.get_current_user())
            self.redirect(self.get_next_url(user), permanent=False)
        else:
            self.finish(self._render())


class MultiLogoutHandler(LogoutHandler):
    pass


class MultiOAuthenticator(Authenticator):

    _auth_provider_list = List(
                    Tuple(
                        Type(GoogleOAuthenticator, OAuthenticator, help='Must be an OAuthenticator'),
                        Type(GoogleLoginHandler, OAuthLoginHandler, help="Must be a OAuthLoginHandler"),
                        Type(GoogleOAuthHandler, OAuthCallbackHandler, help="Must be a OAuthCallbackHandler")
                        )
    ).tag(config=True)

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        subauth_name = self.__subauth_name
        if subauth_name is None:
            # 2019110 A temporary fix for redirect loop and 500 error
            # see: https://github.com/jupyterhub/jupyterhub/blob/66f29e0f5ab21683fe63186336ae3a6fcf2f5bda/jupyterhub/user.py#L539
            # see: https://github.com/jupyterhub/jupyterhub/issues/2683
            # This is not a Hub bug. Instead, it is a multioauthenticator bug and design issue.
            # If hub server restarts and user opens a browser that still has valid cookies for a already logged in user.
            # In this case Hub will skip authentication process,
            # instead it retrieves saved User object from DB and does spawning with it.
            # the subauth_name here is None because Hub restarted and it only gets saved/cached in memory during a full multioauthentication process
            # Return this function here means No authenticator.pre_spawn_start() will be executed any more
            # A workaround: use spawner.run_pre_spawn_hook()
            # see: https://github.com/jupyterhub/jupyterhub/blob/66f29e0f5ab21683fe63186336ae3a6fcf2f5bda/jupyterhub/user.py#L551
            return None
        for auth_tuple in self._auth_provider_list:
            auth_class = auth_tuple[0]
            auth_obj = auth_class(config=self.config)
            if auth_obj.login_service.lower() == subauth_name.lower():
                yield auth_obj.pre_spawn_start(user, spawner)
                break

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__client_id = None
        self.__client_secret = None
        self.__scope = None
        self.__subauth_name = None

    @property
    def client_id(self):

        return self.__client_id

    @property
    def client_secret(self):
        return self.__client_secret

    @property
    def scope(self):
        return self.__scope

    def set_oauth_tokens(self, subauth):
        """
        Caches configured information from the subauthenticator in properties
        """

        self.__client_id = subauth.client_id
        self.__client_secret = subauth.client_secret
        self.__scope = subauth.scope
        self.__subauth_name = subauth.login_service

    def login_url(self, base_url, login_service):
        return url_path_join(base_url, login_service.lower(), 'login')

    def _get_auth_obj(self, handler=None):
        if handler is None:
            raise ValueError("MultiAuthenticator only works with a handler")
        for auth_tuple in self._auth_provider_list:
            login_handler_class = auth_tuple[1]
            if type(handler) is login_handler_class:
                auth_obj = auth_tuple[0](config=self.config)
                return auth_obj
        return None

    def get_login_service(self, handler=None):
        auth_obj = self._get_auth_obj(handler)
        return auth_obj.login_service if auth_obj else None

    def get_callback_url(self, handler=None):
        """
        This is called by oauth2, it thinks that there will just be one
        """
        # import pdb; pdb.set_trace()
        auth_obj = self._get_auth_obj(handler)
        if auth_obj:
            self.set_oauth_tokens(auth_obj)
            return auth_obj.oauth_callback_url
        return "CALLBACK_URL_NOT_SET"

    def validate_username(self, username):
        return super().validate_username(username)

    def normalize_username(self, username):
        return super().normalize_username(username)

    def get_handlers(self, app):

        h = [
            ('/login', MultiLoginHandler),
            ('/logout', MultiLogoutHandler),
        ]
        for auth_tuple in self._auth_provider_list:

            auth_obj = auth_tuple[0](config=self.config)
            login_service = auth_obj.login_service.lower()
            handlers = dict(auth_obj.get_handlers(app))

            login_handler = handlers['/oauth_login']
            callback_handler = handlers['/oauth_callback']
            h.extend([
                (f'/{login_service}/login', login_handler),
                (f'/{login_service}/oauth_callback', callback_handler),
            ])
            if login_service.lower() == 'github':  # 兼容老版本的app
                h.extend([
                    ('/oauth_login', login_handler)
                ])

        return h

    @gen.coroutine
    def authenticate(self, handler, data):
        """
        Delegate authentication to the appropriate authenticator
        """
        # import pdb
        # pdb.set_trace()
        for auth_tuple in self._auth_provider_list:
            auth_class = auth_tuple[0]
            oauth_handler_class = auth_tuple[2]
            if isinstance(handler, oauth_handler_class):
                auth_obj = auth_class(config=self.config)
                auth = yield auth_obj.authenticate(handler, data)
                return auth
        return None
