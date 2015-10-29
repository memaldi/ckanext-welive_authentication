from pylons.controllers.util import redirect
from ckan.common import request
import ckan.lib.base as base


class WeliveAuthenticationController(base.BaseController):
    def login(self):
        return redirect('https://dev.smartcommunitylab.it/aac/cas/login?service=http://172.28.128.30:5000')
