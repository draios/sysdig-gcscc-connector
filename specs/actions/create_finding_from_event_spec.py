from mamba import description, it, before
from expects import expect
from doublex import Spy, Stub, when
from doublex_expects import have_been_called_with

import securecscc
from securecscc import origins

from specs.support import fixtures


with description(securecscc.CreateFindingFromEvent) as self:
    with before.each:
        self.settings = securecscc.Settings()
        self.gcloud_client = Spy(securecscc.GoogleCloudClient)
        self.origin = Stub(origins.Falco)

        self.action = securecscc.CreateFindingFromEvent(self.settings,
                                                        self.gcloud_client,
                                                        self.origin)

    with it('sends parsed finding to Google Cloud Security Command Center'):
        finding = securecscc.Finding(
            finding_id='irrelevant finding id',
            source='irrelevant source',
            category='irrelevant category',
            event_time='irrelevant event_time',
        )
        when(self.origin).create_from(fixtures.event()).returns(finding)

        self.action.run(fixtures.event())

        expect(self.gcloud_client.create_finding)\
            .to(have_been_called_with(finding))
