import http
import json

import securecscc
import falco_server

from mamba import description, context, it, before
from expects import expect, equal
from doublex import Spy, when


from specs.support import fixtures


with description('HTTP Webhook') as self:
    with before.each:
        self.app = falco_server.app.test_client()

        settings = securecscc.Settings()

    with context('POST /'):
        with before.each:
            falco_server.ACTION = Spy(securecscc.CreateFindingFromEvent)

        with it('returns a 201'):
            result = self.app.post('/',
                                   data=fixtures.payload_from_falco(),
                                   content_type='application/json')

            expect(result.status_code).to(equal(http.client.CREATED))

        with it('returns new created finding'):
            finding = {'id': 'irrelevant id'}
            when(falco_server.ACTION).run(fixtures.event_falco()).returns(finding)

            result = self.app.post('/',
                                   data=fixtures.payload_from_falco(),
                                   content_type='application/json')

            expect(json.loads(result.data)).to(equal(finding))
