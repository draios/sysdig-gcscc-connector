from mamba import description, it, before, context
from expects import expect, be_none, have_len, equal, be_below_or_equal

import securecscc
from securecscc import origins, models

from specs.support import fixtures
from specs.support.matchers import be_an_uuid


with description(origins.Falco) as self:
    with before.each:
        self.settings = securecscc.Settings()
        self.mapper = origins.Falco(self.settings)

    with it('uses Falco as source'):
        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.source).to(equal(models.Finding.SOURCE_FALCO))

    with it('uses the rule as category'):
        category = 'Terminal shell in container'

        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.category).to(equal(category))

    with it('uses only seconds from event time'):
        event_time = 1526547969

        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.event_time).to(equal(event_time))

    with it('does not set any url'):
        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.url).to(be_none)

    with context('when checking the finding_id'):
        with it('uses an uuid as id'):
            finding = self.mapper.create_from(fixtures.event_falco())

            expect(finding.finding_id).to(be_an_uuid())

        with it('uses a shorter value than allowed by Google'):
            finding = self.mapper.create_from(fixtures.event_falco())

            expect(finding.finding_id).to(have_len(be_below_or_equal(32)))

    with it('has a resource name empty'):
        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.resource_name).to(be_none)

    with it('adds output'):
        output = "A shell was spawned in a container with an attached terminal (user=root unruffled_hamilton (id=32c415f00958) shell=bash parent=<NA> cmdline=bash  terminal=34816)"

        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.summary).to(equal(output))

    with it('adds priority'):
        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.priority).to(equal('Notice'))

    with it('adds container id'):
        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.container_id).to(equal('32c415f00958'))

    with it('adds container name'):
        finding = self.mapper.create_from(fixtures.event_falco())

        expect(finding.container_name).to(equal('unruffled_hamilton'))

    with it('adds pod name to properties'):
        finding = self.mapper.create_from(fixtures.event_falco_k8s())

        expect(finding.kubernetes_pod_name).to(equal('falco-event-generator-6fd89678f9-cdkvz'))
