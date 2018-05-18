from mamba import description, it, before, context
from expects import expect, have_key, end_with, start_with, have_keys
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

    with it('allows on premise hosts for event url'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding).to(have_key('url', start_with(self.settings.sysdig_url_prefix())))

    with it('extracts url path from security event'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding).to(have_key('url', end_with('/#/events/f:1523007251,t:1523007371/*/*?viewAs=list')))

    with it('retrieves category name from sysdig client'):
        category_name = 'a category name'
        when(self.sysdig_client).find_policy_by_id(59).returns(category_name)

        finding = self.mapper.create_from(fixtures.event())

        expect(finding).to(have_key('category', category_name))

    with it('uses id from security event'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding).to(have_key('id', '530491201430929408'))

    with it('uses the source_id assigned to us from Google'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding).to(have_key('source_id', self.settings.source_id()))

    with it('uses only seconds from event time'):
        finding = self.mapper.create_from(fixtures.event())

        expect(finding).to(have_key('event_time', 1523007311))

    with context('when building properties'):
        with it('adds output'):
            output = "Sensitive file opened for reading by non-trusted program (user=root program=ftest command=ftest -i 25200 -a exfiltration file=/etc/shadow parent=docker-containe gparent=docker-containe ggparent=dockerd gggparent=systemd)"

            finding = self.mapper.create_from(fixtures.event())

            expect(finding).to(have_key('properties', have_key('summary', output)))

        with it('adds severity'):
            finding = self.mapper.create_from(fixtures.event())

            expect(finding).to(have_key('properties', have_key('severity', 4)))

        with it('adds rule type'):
            finding = self.mapper.create_from(fixtures.event())

            expect(finding).to(have_key('properties', have_key('rule.type',
                                                               'RULE_TYPE_FALCO')))

        with it('adds container metadata'):
            container_id = '57c1820a87f1'
            when(self.sysdig_client).find_container_metadata_from_container_id(container_id).returns({'container.stuff': 'FOO'})

            finding = self.mapper.create_from(fixtures.event())

            expect(finding).to(have_key('properties', have_key('container.stuff', 'FOO')))

    with context('when filling asset ids'):
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

    with context('when receving a host event'):
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
