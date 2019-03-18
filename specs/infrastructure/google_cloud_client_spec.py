from datetime import datetime

import securecscc

from mamba import description, it, before, _it
from expects import expect, equal


with description(securecscc.GoogleCloudClient) as self:
    with before.each:
        self.settings = securecscc.Settings()
        self.client = securecscc.GoogleCloudClient(securecscc.Credentials())

    with it('creates the finding'):
        finding = securecscc.Finding(
            source=self.settings.source(),
            category='AUTOMATED_TEST_FOO',
            event_time=self.now(),
            url='http://example.com',
        )

        self.client.create_finding(finding)

    def now(self):
        dt = datetime.utcnow()
        return int((dt - datetime.utcfromtimestamp(0)).total_seconds())

    with _it('retrieves id from hostname'):
        project = 'arboreal-logic-197906'
        zone = 'europe-west3-a'
        hostname = 'gke-demo-default-pool-1af4d30b-hnbq'

        instance_id = self.client.get_instance_id_from_hostname(project,
                                                                zone,
                                                                hostname)

        expect(instance_id).to(equal('6739927742716024409'))
