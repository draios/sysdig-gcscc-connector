import uuid

from expects.matchers import Matcher


class be_an_uuid(Matcher):
    def _match(self, value):
        try:
            uuid.UUID(value)
            return True, ['is a valid UUID']
        except:
            return False, ['is not a valid UUID']
