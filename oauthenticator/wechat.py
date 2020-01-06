"""
Custom Authenticator to use WeChat OAuth with JupyterHub

wechat OAuth docs: https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
"""


import json
import os
import re
import string

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError

from jupyterhub.auth import LocalAuthenticator

from traitlets import List, Set, Unicode

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator, OAuthCallbackHandler


WECHAT_HOST = os.environ.get('WECHAT_HOST') or 'weixin.qq.com'
WECHAT_API = 'api.{}'.format(WECHAT_HOST)
WECHAT_PROTOCOL = 'https'

def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
    }


class WeChatMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "{}://open.{}/connect/qrconnect".format(WECHAT_PROTOCOL, WECHAT_HOST)
    _OAUTH_ACCESS_TOKEN_URL = "{}://{}/sns/oauth2/access_token".format(WECHAT_PROTOCOL, WECHAT_API)


class WeChatLoginHandler(OAuthLoginHandler, WeChatMixin):
    def authorize_redirect(self, *args, **kwargs):
        """Add appid, secret to redirect params"""
        extra_params = kwargs.setdefault('extra_params', {})
        if self.authenticator.client_id:
            extra_params["appid"] = self.authenticator.client_id

        return super().authorize_redirect(*args, **kwargs)

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        login_service = self.authenticator.login_service
        if not login_service and hasattr(self.authenticator, 'get_login_service'):
            login_service = self.authenticator.get_login_service(self) or ''

        self.log.info('OAuth redirect: %r', redirect_uri)
        self.statsd.incr(f'login.request.{login_service.lower()}')
        state = self.get_state()
        self.set_state_cookie(state)
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            scope=self.authenticator.scope,
            extra_params={'state': state},
            response_type='code')


class WeChatCallbackHandler(OAuthCallbackHandler):
    pass


class WeChatOAuthenticator(OAuthenticator):

    login_service = "Wechat"

    client_id_env = 'WECHAT_APP_ID'
    client_secret_env = 'WECHAT_APP_SECRET'
    login_handler = WeChatLoginHandler
    callback_handler = WeChatCallbackHandler

    async def authenticate(self, handler, data=None):
        """We set up auth_state based on additional WeChat info if we
        receive it.
        """
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # WeChat specifies a POST request yet requires URL parameters
        params = dict(
            appid=self.client_id,
            secret=self.client_secret,
            code=code,
            grant_type='authorization_code',
        )

        url = url_concat("%s://%s/sns/oauth2/access_token" % (WECHAT_PROTOCOL, WECHAT_API),
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body=''  # Body is required for a POST...
                          )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if 'access_token' in resp_json and 'openid' in resp_json:
            access_token = resp_json['access_token']
            openid = resp_json['openid']
        elif 'errmsg' in resp_json:
            raise HTTPError(403,
                "access token or openid was not returned: {}".format(
                    resp_json['errmsg']))
        else:
            raise HTTPError(500,
                "Bad response: %s".format(resp))

        # Determine who the logged in user is
        params = dict(
            openid=openid,
            access_token=access_token,
        )
        url = url_concat(
            "{}://{}/sns/userinfo".format(WECHAT_PROTOCOL, WECHAT_API),
            params
        )
        req = HTTPRequest(url, method="GET", headers=_api_headers(access_token))
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = '@'.join([
            str(resp_json['openid']), self.login_service
        ])
        # username is now the WeChat userid.
        if not username:
            return None

        userdict = {"name": username}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        # Save the access token and full WeChat reply (name, openid, nickname) in auth state
        # These can be used for user provisioning in the Lab/Notebook environment.
        # e.g.
        #  1) stash the access token
        #  2) use the WeChat openid as the id
        #  3) set up name/email for .gitconfig
        auth_state['access_token'] = access_token
        # store the whole user model in auth_state.wechat_user
        auth_state['wechat_user'] = resp_json
        auth_state['wechat_user']['login'] = resp_json.get('nickname')
        auth_state['wechat_user']['avatar_url'] = resp_json.get('headimgurl')

        return userdict


class LocalWeChatOAuthenticator(LocalAuthenticator, WeChatOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
