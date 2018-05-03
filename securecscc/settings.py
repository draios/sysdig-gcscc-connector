import os


class Settings:
    def source_id(self):
        return 'SYSDIG'

    def organization(self):
        return 'organizations/{}'.format(os.environ['ORG_ID'])

    def project(self):
        return os.environ['COMPUTE_PROJECT_ID']

    def zone(self):
        return os.environ['COMPUTE_ZONE']

    def sysdig_url_prefix(self):
        return os.environ.get('SYSDIG_URL_PREFIX', 'https://secure.sysdig.com')

    def webhook_url(self):
        return os.environ['WEBHOOK_URL']

    def webhook_authentication_token(self):
        return 'CSCC {}'.format(os.environ['WEBHOOK_AUTHENTICATION_TOKEN'])
