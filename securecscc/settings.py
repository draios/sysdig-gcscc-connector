import os


class Settings(object):
    def organization(self):
        return 'organizations/{}'.format(os.environ['ORG_ID'])

    def source(self):
        return 'organizations/{}/sources/{}'.format(os.environ['ORG_ID'], os.environ['SOURCE_ID'])

    def sysdig_url_prefix(self):
        return os.environ.get('SYSDIG_URL_PREFIX', 'https://secure.sysdig.com')

    def webhook_url(self):
        return os.environ['WEBHOOK_URL']

    def webhook_authentication_token(self):
        return os.environ['WEBHOOK_AUTHENTICATION_TOKEN']
