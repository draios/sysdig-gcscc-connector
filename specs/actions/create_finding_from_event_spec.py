from mamba import description, it, before, context
from expects import expect, have_key, end_with, start_with, have_keys
from doublex import Spy, when
from doublex_expects import have_been_called_with

import securecscc

from specs.support import fixtures


with description(securecscc.CreateFindingFromEvent) as self:
    with before.each:
        self.settings = securecscc.Settings()
        self.organization = self.settings.organization()

        self.gcloud_client = Spy(securecscc.GoogleCloudClient)
        self.sysdig_client = Spy(securecscc.SysdigSecureClient)

        self.action = securecscc.CreateFindingFromEvent(self.settings,
                                                        self.gcloud_client,
                                                        self.sysdig_client)

    with it('allows on premise hosts for event url'):
        self.action.run(fixtures.event())

        expect(self.gcloud_client.create_finding)\
            .to(have_been_called_with(self.organization,
                                      have_key('url', start_with(self.settings.sysdig_url_prefix()))))

    with it('extracts url path from security event'):
        self.action.run(fixtures.event())

        expect(self.gcloud_client.create_finding)\
            .to(have_been_called_with(self.organization,
                                      have_key('url', end_with('/#/events/f:1523007251,t:1523007371/*/*?viewAs=list'))))

    with it('retrieves category name from sysdig client'):
        category_name = 'a category name'
        when(self.sysdig_client).find_policy_by_id(59).returns(category_name)

        self.action.run(fixtures.event())

        expect(self.gcloud_client.create_finding)\
            .to(have_been_called_with(self.organization,
                                      have_key('category', category_name)))

    with it('uses id from security event'):
        self.action.run(fixtures.event())

        expect(self.gcloud_client.create_finding)\
            .to(have_been_called_with(self.organization,
                                      have_key('id', '530491201430929408')))

    with it('uses the source_id assigned to us from Google'):
        self.action.run(fixtures.event())

        expect(self.gcloud_client.create_finding)\
            .to(have_been_called_with(self.organization,
                                      have_key('source_id', self.settings.source_id())))

    with it('uses only seconds from event time'):
        self.action.run(fixtures.event())

        expect(self.gcloud_client.create_finding)\
            .to(have_been_called_with(self.organization,
                                      have_key('event_time', 1523007311)))

    with context('when building properties'):
        with it('adds output'):
            output = "Sensitive file opened for reading by non-trusted program (user=root program=ftest command=ftest -i 25200 -a exfiltration file=/etc/shadow parent=docker-containe gparent=docker-containe ggparent=dockerd gggparent=systemd)"

            self.action.run(fixtures.event())

            expect(self.gcloud_client.create_finding)\
                .to(have_been_called_with(self.organization,
                                          have_key('properties',
                                                   have_key('summary', output))))

        with it('adds severity'):
            self.action.run(fixtures.event())

            expect(self.gcloud_client.create_finding)\
                .to(have_been_called_with(self.organization,
                                          have_key('properties',
                                                   have_key('severity', 4))))

        with it('adds rule type'):
            self.action.run(fixtures.event())

            expect(self.gcloud_client.create_finding)\
                .to(have_been_called_with(self.organization,
                                          have_key('properties',
                                                   have_key('rule.type', 'RULE_TYPE_FALCO'))))

        with it('adds container metadata'):
            container_id = '57c1820a87f1'
            when(self.sysdig_client).find_container_metadata_from_container_id(container_id).returns({'container.stuff': 'FOO'})

            self.action.run(fixtures.event())

            expect(self.gcloud_client.create_finding)\
                .to(have_been_called_with(self.organization,
                                          have_key('properties',
                                                   have_key('container.stuff', 'FOO'))))

    with context('when filling asset ids'):
        with context('when filling container image'):
            with before.each:
                self. container_id = '57c1820a87f1'

            with it('queries sysdigcloud for its image id and adds to asset ids'):
                container_image = 'gcr.io/google-containers/prometheus-to-sd@sha256:5831390762c790b0375c202579fd41dd5f40c71950f7538adbe14b0c16f35d56'

                when(self.sysdig_client).find_container_image_from_container_id(self.container_id).returns(container_image)

                self.action.run(fixtures.event())

                expect(self.gcloud_client.create_finding)\
                    .to(have_been_called_with(self.organization,
                                              have_key('asset_ids', [container_image])))

            with context('and is not an image stored in Google Registry'):
                with it('returns organization as asset id'):
                    container_image = 'hub.docker.com'

                    when(self.sysdig_client).find_container_image_from_container_id(self.container_id).returns(container_image)

                    self.action.run(fixtures.event())

                    expect(self.gcloud_client.create_finding)\
                        .to(have_been_called_with(self.organization,
                                                have_key('asset_ids', [self.organization])))

        with context('when filling instance id'):
            with before.each:
                self.mac = "06:90:90:7f:15:ea"
                self.hostname = 'any hostname'

            with it('queries google for its id and adds to asset ids'):
                an_id = 'irrelevant id'
                instance_image_id = '{}/instance/irrelevant id'.format(self.settings.project())
                when(self.sysdig_client).find_host_by_mac(self.mac).returns(self.hostname)
                when(self.gcloud_client).get_instance_id_from_hostname(self.settings.project(), self.settings.zone(), self.hostname).returns(an_id)

                self.action.run(fixtures.event())

                expect(self.gcloud_client.create_finding)\
                    .to(have_been_called_with(self.organization,
                                              have_key('asset_ids', [instance_image_id])))

            with context('and mac is not found on sysdig'):
                with it('returns organization as asset id'):
                    when(self.sysdig_client).find_host_by_mac(self.mac).returns(None)

                    self.action.run(fixtures.event())

                    expect(self.gcloud_client.create_finding)\
                        .to(have_been_called_with(self.organization,
                                                  have_key('asset_ids', [self.organization])))

            with context('and hostname is not found on google compute'):
                with it('returns organization as asset id'):
                    when(self.sysdig_client)\
                        .find_host_by_mac(self.mac).returns(self.hostname)
                    when(self.gcloud_client)\
                        .get_instance_id_from_hostname(self.settings.project(),
                                                       self.settings.zone(),
                                                       self.hostname).returns(None)

                    self.action.run(fixtures.event())

                    expect(self.gcloud_client.create_finding)\
                        .to(have_been_called_with(self.organization,
                                                  have_key('asset_ids', [self.organization])))

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

            result = self.action.run(fixtures.event_host())

            expect(self.gcloud_client.create_finding)\
                .to(have_been_called_with(self.organization,
                                            have_key('asset_ids', [instance_image_id])))

        with it('does not add any container metadata'):
            self.action.run(fixtures.event())

            expect(self.gcloud_client.create_finding)\
                .to(have_been_called_with(self.organization,
                                          have_key('properties', have_keys('summary', 'severity', 'rule.type'))))

    with context('when creating from falco'):
        with it('uses the source_id assigned to us from Google'):
            finding = self.action.run(fixtures.event_falco())

            expect(finding).to(have_key('source_id', self.settings.source_id()))
