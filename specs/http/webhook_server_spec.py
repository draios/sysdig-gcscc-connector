import http
import json

import securecscc
import webhook_server

from mamba import description, context, it, before
from expects import expect, equal
from doublex import Spy, when


from specs.support import fixtures


with description('Sysdig Secure HTTP Webhook') as self:
    with before.each:
        self.app = webhook_server.app.test_client()

        settings = securecscc.Settings()
        self.authorization_headers = {'Authorization': settings.webhook_authentication_token()}

    with context('GET /'):
        with it('is alive'):
            result = self.app.get('/')

            expect(result.status_code).to(equal(http.client.OK))

    with context('POST /events'):
        with before.each:
            webhook_server.ACTION = Spy(securecscc.CreateFindingFromEvent)

        with it('returns a 201'):
            result = self.app.post('/events',
                                   data=fixtures.payload_from_webhook(),
                                   content_type='application/json',
                                   headers=self.authorization_headers)

            expect(result.status_code).to(equal(http.client.CREATED))

        with it('returns new created finding'):
            finding = {'id': 'irrelevant id'}
            when(webhook_server.ACTION).run(fixtures.event_in_webhook()).returns(finding)

            result = self.app.post('/events',
                                   data=fixtures.payload_from_webhook(),
                                   content_type='application/json',
                                   headers=self.authorization_headers)

            expect(json.loads(result.data)).to(equal([finding]))

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
