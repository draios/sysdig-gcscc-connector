from mamba import description, it
from expects import expect
from doublex import Spy
from doublex_expects import have_been_called_with

import securecscc


with description(securecscc.CreateSecuritySource) as self:
    with it('creates security source in Google Cloud Security Command Center'):
        self.settings = securecscc.Settings()
        self.gcloud_client = Spy(securecscc.GoogleCloudClient)

        display_name = 'irrelevant display name'
        description = 'irrelevant description'

        self.action = securecscc.CreateSecuritySource(
            self.settings,
            self.gcloud_client
        )

        security_source = self.action.run(display_name, description)

        expect(self.gcloud_client.create_security_source)\
            .to(have_been_called_with(self.settings.organization(),
                                      display_name,
                                      description))
