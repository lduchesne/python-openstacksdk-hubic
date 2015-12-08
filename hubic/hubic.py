# Copyright (c) 2015, Laurent Duchesne <l@urent.org>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re
import time
import string
import random

from keystoneauth1.session import Session
from keystoneclient.exceptions import AuthorizationFailure

def random_str_generator(size=6, chars=string.ascii_uppercase + string.digits):
    """Random string generator.

    Written by Ignacio Vazquez-Abrams.
    Source: http://stackoverflow.com/a/2257449/4871858
    """

    return ''.join(random.choice(chars) for _ in range(size))


class HubiCAuthenticator:
    """Provide a HubiC authentication interface compatible with the OpenStack SDK.

    This is necessary as HubiC doesn't provide OpenStack-compatible identity
    services, but still provide a compatible object store (v1).

	References:
		- https://hubic.com/en/
		- https://api.hubic.com/

    :param string client_id: The HubiC client identifier.
    :param string client_secret: The HubiC client secret.
    :param string email: The account email address.
    :param string password: The account password.
    :param string redirect_uri: The registered redirect URI (optional).
    """

    def __init__(self, client_id, client_secret, email, password,
                 redirect_uri="http://localhost/", **kwargs):
        self.email         = email
        self.password      = password
        self.client_id     = client_id
        self.client_secret = client_secret
        self.redirect_uri  = redirect_uri

        self.auth_token = None
        self.endpoint   = None

        self.access_token  = None
        self.refresh_token = None


    def get_headers(self, session, **kwargs):
        """Get the authentication header.

        If the current session has not been authenticated, this will trigger a
        new authentication to the HubiC OAuth service.

        :param keystoneclient.Session session: The session object to use for
                                               queries.

        :raises keystoneclient.exceptions.AuthorizationFailure: if something
                                                                goes wrong.

        :returns: The headers used for authenticating requests.
        :rtype: dict
        """

        if self.auth_token is None:
            try:
                self._refresh_tokens(session)
                self._fetch_credentials(session)
            except:
                raise AuthorizationFailure()

        return {
            'X-Auth-Token': self.auth_token,
        }


    def get_endpoint(self, session, **kwargs):
        """Get the HubiC storage endpoint uri.

        If the current session has not been authenticated, this will trigger a
        new authentication to the HubiC OAuth service.

        :param keystoneclient.Session session: The session object to use for
                                               queries.

        :raises keystoneclient.exceptions.AuthorizationFailure: if something
                                                                goes wrong.

        :returns: The uri to use for object-storage v1 requests.
        :rtype: string
        """

        if self.endpoint is None:
            try:
                self._refresh_tokens(session)
                self._fetch_credentials(session)
            except:
                raise AuthorizationFailure()

        return self.endpoint


    def get_connection_params(self, session, **kwargs):
        """Connection parameters used for all requests.

        :returns: An empty dictionary.
        :rtype: dict
        """

        return {}


    def invalidate(self):
        """Invalidate the current authenticator.

        Once this has been called, any call to get_endpoint or get_headers will
        trigger a new authentication to the HubiC OAuth service.
        """

        self.endpoint = None
        self.auth_token = None


    def _refresh_tokens(self, session):
        """Request an access and a refresh token from the HubiC API.

        Those tokens are mandatory and will be used for subsequent file
        operations. They are not returned and will be stored internaly.

        :param keystoneclient.Session session: The session object to use for
                                               queries.

        :raises keystoneclient.exceptions.AuthorizationFailure: if something
                                                                goes wrong.
        """

        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        if self.refresh_token is None:
            # if we don't have a refresh token, we need an authorization token
            # first
            payload['grant_type']   = 'authorization_code'
            payload['code']         = self._get_authorization_token(session)
            payload['redirect_uri'] = self.redirect_uri
        else:
            # when we have a refresh token, we DON'T need an authorization
            # token to request a new one
            payload['grant_type']    = 'refresh_token'
            payload['refresh_token'] = self.refresh_token

        r = session.post("https://api.hubic.com/oauth/token",
                         params=params,
                         data=payload,
                         authenticated=False)
        if r.status_code != 200:
            raise AuthorizationFailure()

        response = r.json()
        if 'error' in response:
            raise AuthorizationFailure()

        self.access_token = response['access_token']

        # refresh_token entry will not be there is we are just refreshing an
        # old token.
        if 'refresh_token' in response:
            self.refresh_token = response['refresh_token']


    def _fetch_credentials(self, session):
        """Fetch the endpoint URI and authorization token for this session.

        Those two information are the basis for all future calls to the Swift
        (OpenStack) API for the storage container.

        :param keystoneclient.Session session: The session object to use for
                                               queries.

        :raises keystoneclient.exceptions.AuthorizationFailure: if something
                                                                goes wrong.
        """

        headers = {
            'Authorization': 'Bearer {0}'.format(self.access_token),
        }

        r = session.get("https://api.hubic.com/1.0/account/credentials",
                        headers=headers,
                        authenticated=False)
        response = r.json()

        # if we get an error here, the OpenStack SDK will take care to try
        # again for us.
        if 'error' in response:
            raise AuthorizationFailure()

        self.endpoint   = response['endpoint']
        self.auth_token = response['token']


    def _get_authorization_token(self, session):
        """Load the HubiC form, submit it and return an authorization token.

        This will load the HTML form to accept if the application can access
        the user account and submit the form using the user's credentials.

        :raises keystoneclient.exceptions.AuthorizationFailure: if something
                                                                goes wrong.

        :returns: The (short lived) authorization code to use to get the
                  refresh token.
        :rtype: string
        """

        request_scope = 'account.r,credentials.r'

        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': request_scope,
            'state': random_str_generator(),
        }

        r = session.get("https://api.hubic.com/oauth/auth",
                        params=params,
                        authenticated=False)
        if r.status_code != 200:
            raise AuthorizationFailure()

        oauth_match = re.search(r'name="oauth" value="([0-9]+)"', r.text)
        if oauth_match is None:
            raise AuthorizationFailure()

        oauth_value = oauth_match.group(1)
        if oauth_value is None:
            AuthorizationFailure()

        payload = {
            'oauth': oauth_value,
            'action': 'accepted',
            'account': 'r',
            'credentials': 'r',
            'login': self.email,
            'user_pwd': self.password,
        }

        # this is necessary because the API will return a 509 error
        # (bandwidth exceeded) if we don't wait a little
        time.sleep(2)

        headers = {
            'Referer': r.url,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        r = session.post("https://api.hubic.com/oauth/auth",
                         headers=headers,
                         data=payload,
                         redirect=False,
                         authenticated=False)
        if r.status_code != 302:
            raise AuthorizationFailure()

        # location looks like this, and we need the code:
        # http://localhost/?code=...&scope=account.r&state=randomstring
        location_info = dict(
            map(lambda item: item.split('='),
                r.headers['location'].split('?')[1].split('&')
            )
        )
        assert (
            'code'  in location_info and
            'scope' in location_info and location_info['scope'] == request_scope and
            'state' in location_info and location_info['state'] == params['state']
        )

        return location_info['code']


if __name__ == "__main__":
    configuration = {
        'client_id': '',
        'client_secret': '',
        'email': '',
        'password': '',
    }

    authenticator = HubiCAuthenticator(**configuration)

    from openstack import connection
    conn = connection.Connection(
        session=Session(auth=authenticator),
        authenticator=authenticator,
    )

    # just list the containers to see if this works
    print(list(conn.object_store.containers()))
