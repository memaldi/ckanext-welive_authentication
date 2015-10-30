from ckan.common import request
from routes.mapper import SubMapper
import ckan.logic as logic
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import logging
import requests
import xmltodict
import pylons
import ConfigParser
import os
import uuid

log = logging.getLogger(__name__)

config = ConfigParser.ConfigParser()
config.read(os.environ['CKAN_CONFIG'])

PLUGIN_SECTION = 'plugin:authentication'
VALIDATION_URL = config.get(PLUGIN_SECTION, 'validation_url')

MAIN_SECTION = 'app:main'
CKAN_SITE_URL = config.get(MAIN_SECTION, 'ckan.site_url')


def user_update(context, data_dict=None):
    return {'success': False, 'message': 'Not allowed to update user profile'}


class Welive_AuthenticationPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IAuthFunctions)

    # IAuthFunctions

    def get_auth_functions(self):
        return {'user_update': user_update}

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
            response = requests.get(
                VALIDATION_URL,
                params={'service': CKAN_SITE_URL, 'ticket': ticket}
            )

            response_dict = xmltodict.parse(response.text)
            username = None
            if 'cas:serviceResponse' in response_dict:
                if 'cas:authenticationSuccess' in response_dict['cas:serviceResponse']:
                    if 'cas:username' in response_dict['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes']:
                        print 'hey'
                        username = response_dict['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes']['cas:username']
                        print username
                    elif 'cas:OIDC_CLAIM_email' in response_dict['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes']:
                        username = response_dict['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes']['cas:OIDC_CLAIM_email']
            if username is not None:
                try:
                    user = toolkit.get_action('user_show')(
                        context={},
                        data_dict={'id': username})
                    toolkit.c.user = user['name']
                    pylons.session['ckanext-welive-user'] = user['name']
                    pylons.session.save()
                except logic.NotFound:
                    user = model.User(name=username,
                                      email=username,
                                      password=str(uuid.uuid4()))
                    user.save()
                    model.repo.commit()
                    toolkit.c.user = user.name
                    pylons.session['ckanext-welive-user'] = user.name
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
