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

    with it('retrieves id from hostname'):
        hostname = 'gke-sysdig-work-default-pool-a1022875-j81z'

        instance_id = self.client.get_resource_name_from_hostname(
            self.settings.organization(),
            hostname
        )

        expect(instance_id).to(equal('//compute.googleapis.com/projects/sysdig-204815/zones/europe-west3-a/instances/96321670362563295'))
