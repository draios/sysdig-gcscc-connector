import uuid
import securecscc

from expects.matchers import Matcher


class be_an_uuid(Matcher):
    def _match(self, value):
        try:
            uuid.UUID(value)
            return True, ['is a valid UUID']
        except:
            return False, ['is not a valid UUID']


class be_the_organization_resource_name(Matcher):
    def __init__(self):
        self.settings = securecscc.Settings()

    def _match(self, value):
        return value == '//cloudresourcemanager.googleapis.com/{}'.format(self.settings.organization()), ['is the organization resource name']
