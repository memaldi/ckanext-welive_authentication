from pylons.controllers.util import redirect
import ckan.lib.base as base
import ConfigParser
import os

config = ConfigParser.ConfigParser()
config.read(os.environ['CKAN_CONFIG'])

PLUGIN_SECTION = 'plugin:authentication'
LOGIN_URL = config.get(PLUGIN_SECTION, 'login_url')

MAIN_SECTION = 'app:main'
CKAN_SITE_URL = config.get(MAIN_SECTION, 'ckan.site_url')


class WeliveAuthenticationController(base.BaseController):
    def login(self):
        return redirect('%s?service=%s' % (LOGIN_URL, CKAN_SITE_URL))
