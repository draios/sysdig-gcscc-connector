import uuid
from datetime import datetime

import securecscc

from mamba import description, it, before, context
from expects import expect, equal, have_key


with description(securecscc.GoogleCloudClient) as self:
    with before.each:
        self.client = securecscc.GoogleCloudClient(securecscc.Credentials())

    with context('when creating the finding'):
        with before.each:
            self._id = str(uuid.uuid4())
            self.source_id = 'GOOGLE_ANOMALY_DETECTION'
            organization = "organizations/544901558763"

            source_finding = {
                'id': self._id,
                'category': 'AUTOMATED_TEST',
                'asset_ids': ['ASSET_ID_TO_REPLACE'],
                'source_id': self.source_id,
                'event_time': self.now(),
                'url': 'http://example.com',
                'properties': {
                    'dotted.key': 'Do. Or do not. There is no try.',
                    'severity': 4
                }
            }

            self.created = self.client.create_finding(organization,
                                                      source_finding)

        with it('creates the finding'):
            expect(self.created.id).to(equal(self._id))
            expect(self.created.asset_id).to(equal('ASSET_ID_TO_REPLACE'))
            expect(self.created.scanner_id).to(equal(self.source_id))

        with it('uses underscores instead of dots in property keys'):
            expect(self.created.properties).to(have_key('dotted_key'))

        def now(self):
            dt = datetime.utcnow()
            return int((dt - datetime.utcfromtimestamp(0)).total_seconds())

    with it('retrieves id from hostname'):
        project = 'arboreal-logic-197906'
        zone = 'europe-west3-a'
        hostname = 'gke-demo-default-pool-1af4d30b-hnbq'

        instance_id = self.client.get_instance_id_from_hostname(project,
                                                                zone,
                                                                hostname)

        expect(instance_id).to(equal('6739927742716024409'))
