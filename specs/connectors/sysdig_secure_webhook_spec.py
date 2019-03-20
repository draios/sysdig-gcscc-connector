import http
import json

import securecscc
from connectors import sysdig_secure_webhook

from mamba import description, context, it, before
from expects import expect, equal
from doublex import Spy, when


from specs.support import fixtures


with description('Sysdig Secure HTTP Webhook') as self:
    with before.each:
        self.app = sysdig_secure_webhook.app.test_client()

        settings = securecscc.Settings()
        self.authorization_headers = {'Authorization': settings.webhook_authentication_token()}

    with context('GET /health'):
        with it('is alive'):
            result = self.app.get('/health')

            expect(result.status_code).to(equal(http.client.OK))

    with context('POST /events'):
        with before.each:
            sysdig_secure_webhook.ACTION = Spy(securecscc.CreateFindingFromEvent)

            self.finding = securecscc.Finding(
                finding_id='irrelevant finding id',
                source='irrelevant source',
                category='irrelevant category',
                event_time='irrelevant event_time',
            )
            when(sysdig_secure_webhook.ACTION).run(fixtures.event_in_webhook()).returns(self.finding)

        with it('returns a 201'):
            result = self.app.post('/events',
                                   data=fixtures.payload_from_webhook(),
                                   content_type='application/json',
                                   headers=self.authorization_headers)

            expect(result.status_code).to(equal(http.client.CREATED))

        with it('returns new created finding'):
            result = self.app.post('/events',
                                   data=fixtures.payload_from_webhook(),
                                   content_type='application/json',
                                   headers=self.authorization_headers)

            expect(json.loads(result.data)).to(equal([self.finding.to_dict()]))

        with context('when authentication header is not present'):
            with it('returns a 403'):
                result = self.app.post('/events',
                                       data=fixtures.payload_from_webhook(),
                                       content_type='application/json')

                expect(result.status_code).to(equal(http.client.FORBIDDEN))

        with context('when authentication token does not match'):
            with it('returns a 403'):
                result = self.app.post('/events',
                                       data=fixtures.payload_from_webhook(),
                                       content_type='application/json',
                                       headers={'Authorization': 'CSCC foobar'})

                expect(result.status_code).to(equal(http.client.FORBIDDEN))
