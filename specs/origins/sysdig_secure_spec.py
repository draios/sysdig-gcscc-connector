from mamba import description, it, before, context, _context
from expects import expect, have_key, end_with, start_with, have_keys, have_len, equal, be_below_or_equal
from doublex import Stub, when

import securecscc
from securecscc import origins

from specs.support import fixtures


with description(origins.SysdigSecure) as self:
    with before.each:
        self.settings = securecscc.Settings()
        self.sysdig_client = Stub(securecscc.SysdigSecureClient)
        self.gcloud_client = Stub(securecscc.GoogleCloudClient)
        self.mapper = origins.SysdigSecure(self.settings,
                                           self.sysdig_client,
                                           self.gcloud_client)

        self.organization = self.settings.organization()

    with context('when checking the finding_id'):
        with it('uses id from security event'):
            finding = self.mapper.create_from(fixtures.event())

            expect(finding.finding_id).to(equal('530491201430929408'))

        with it('uses a shorter value than allowed by Google'):
            finding = self.mapper.create_from(fixtures.event())

            expect(finding.finding_id).to(have_len(be_below_or_equal(32)))

    with it('uses Sysdig Secure as source'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding.source).to(equal(self.settings.source()))

    with it('uses only seconds from event time'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding.event_time).to(equal(1523007311))

    with it('retrieves category name from sysdig client'):
        category_name = 'a category name'
        when(self.sysdig_client).find_policy_by_id(59).returns(category_name)

        finding = self.mapper.create_from(fixtures.event())

        expect(finding.category).to(equal(category_name))

    with context('when building the URL'):
        with it('allows setting an url for on premise instances'):
            finding = self.mapper.create_from(fixtures.event())

            expect(finding.url).to(start_with(self.settings.sysdig_url_prefix()))

        with it('extracts url path from security event'):
            finding = self.mapper.create_from(fixtures.event())

            expect(finding.url).to(end_with('/#/events/f:1523007251,t:1523007371/*/*?viewAs=list'))

    with it('adds output'):
        output = "Sensitive file opened for reading by non-trusted program (user=root program=ftest command=ftest -i 25200 -a exfiltration file=/etc/shadow parent=docker-containe gparent=docker-containe ggparent=dockerd gggparent=systemd)"

        finding = self.mapper.create_from(fixtures.event())

        expect(finding.summary).to(equal(output))

    with it('adds severity'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding.severity).to(equal(4))

    with it('adds rule type'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding.rule_type).to(equal('RULE_TYPE_FALCO'))

    with it('retrieves container metadata'):
        container_id = '57c1820a87f1'
        when(self.sysdig_client).find_container_metadata_from_container_id(container_id).returns({'container.stuff': 'FOO'})

        finding = self.mapper.create_from(fixtures.event())

        expect(finding.container_metadata).to(have_key('container.stuff', 'FOO'))

    with _context('when filling asset ids'):
        with context('when filling container image'):
            with before.each:
                self. container_id = '57c1820a87f1'

            with it('queries sysdigcloud for its image id and adds to asset ids'):
                container_image = 'gcr.io/google-containers/prometheus-to-sd@sha256:5831390762c790b0375c202579fd41dd5f40c71950f7538adbe14b0c16f35d56'
                when(self.sysdig_client).find_container_image_from_container_id(self.container_id).returns(container_image)

                finding = self.mapper.create_from(fixtures.event())

                expect(finding).to(have_key('asset_ids', [container_image]))

            with context('and is not an image stored in Google Registry'):
                with it('returns organization as asset id'):
                    container_image = 'hub.docker.com'
                    when(self.sysdig_client).find_container_image_from_container_id(self.container_id).returns(container_image)

                    finding = self.mapper.create_from(fixtures.event())

                    expect(finding).to(have_key('asset_ids', [self.organization]))

        with context('when filling instance id'):
            with before.each:
                self.mac = "06:90:90:7f:15:ea"
                self.hostname = 'any hostname'

            with it('queries google for its id and adds to asset ids'):
                an_id = 'irrelevant id'
                instance_image_id = '{}/instance/irrelevant id'.format(self.settings.project())
                when(self.sysdig_client).find_host_by_mac(self.mac).returns(self.hostname)
                when(self.gcloud_client).get_instance_id_from_hostname(self.settings.project(), self.settings.zone(), self.hostname).returns(an_id)

                finding = self.mapper.create_from(fixtures.event())

                expect(finding).to(have_key('asset_ids', [instance_image_id]))

            with context('and mac is not found on sysdig'):
                with it('returns organization as asset id'):
                    when(self.sysdig_client).find_host_by_mac(self.mac).returns(None)

                    finding = self.mapper.create_from(fixtures.event())

                    expect(finding).to(have_key('asset_ids', [self.organization]))

            with context('and hostname is not found on google compute'):
                with it('returns organization as asset id'):
                    when(self.sysdig_client)\
                        .find_host_by_mac(self.mac).returns(self.hostname)
                    when(self.gcloud_client)\
                        .get_instance_id_from_hostname(self.settings.project(),
                                                       self.settings.zone(),
                                                       self.hostname).returns(None)

                    finding = self.mapper.create_from(fixtures.event())

                    expect(finding).to(have_key('asset_ids', [self.organization]))

    with _context('when receving a host event'):
        with before.each:
            self.mac = "42:01:0a:9c:00:06"

        with it('includes instance id in asset ids'):
            hostname = "irrelevant hostname"
            an_id = "irrelevant id"
            instance_image_id = '{}/instance/{}'.format(self.settings.project(), an_id)
            when(self.sysdig_client)\
                .find_host_by_mac(self.mac).returns(hostname)

            when(self.gcloud_client).get_instance_id_from_hostname(self.settings.project(),
                                                                   self.settings.zone(),
                                                                   hostname).returns(an_id)

            finding = self.mapper.create_from(fixtures.event_host())

            expect(finding).to(have_key('asset_ids', [instance_image_id]))

        with it('does not add any container metadata'):
            finding = self.mapper.create_from(fixtures.event())

            expect(finding).to(have_key('properties', have_keys('summary', 'severity', 'rule.type')))
