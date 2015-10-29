from ckan.common import request
from routes.mapper import SubMapper
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
import requests
import xmltodict
import pylons

log = logging.getLogger(__name__)


class Welive_AuthenticationPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IRoutes, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'welive_authentication')

    # IAuthenticator

    def identify(self):
        log.debug('identify')
        user_name = pylons.session.get('ckanext-welive-user')
        if user_name:
            # We've found a logged-in user. Set c.user to let CKAN know.
            toolkit.c.user = user_name
        elif 'ticket' in request.GET:
            ticket = request.GET.get('ticket')
            url = 'http://172.28.128.30:5000'
            response = requests.get(
                'https://dev.smartcommunitylab.it/aac/cas/serviceValidate?service=%s&ticket=%s' % (url, ticket))

            response_dict = xmltodict.parse(response.text)
            username = None
            if 'serviceResponse' in response_dict:
                if 'authenticationSuccess' in response_dict['serviceResponse']:
                    if 'username' in response_dict['serviceResponse']['authenticationSuccess']['attributes']:
                        username = response_dict['serviceResponse']['authenticationSuccess']['attributes']['username']
                    elif 'OIDC_CLAIM_email' in response_dict['serviceResponse']['authenticationSuccess']['attributes']:
                        username = response_dict['serviceResponse']['authenticationSuccess']['attributes']['OIDC_CLAIM_email']

            if username is not None:
                user = toolkit.get_action('user_show')(
                    context={},
                    data_dict={'id': username})
                if user is not None:
                    toolkit.c.user = user
                else:
                    user = toolkit.get_action('user_create')(
                        context={'ignore_auth': True},
                        data_dict={'name': username})
                toolkit.c.user = user['name']
                pylons.session['ckanext-welive-user'] = user['name']
                pylons.session.save()

    def login(self):
        log.debug('login')
        pass

    def logout(self):
        log.debug('logout')
        if 'ckanext-welive-user' in pylons.session:
            del pylons.session['ckanext-welive-user']
        pylons.session.save()

    def abort(self, status_code, detail, headers, comment):
        log.debug('abort')
        return status_code, detail, headers, comment

    # IRoutes

    def before_map(self, map):
        with SubMapper(
                map,
                controller='ckanext.welive_authentication.controller:WeliveAuthenticationController') as m:
            m.connect('login', '/user/login',
                      action='login', ckan_icon='cogs')

        return map
