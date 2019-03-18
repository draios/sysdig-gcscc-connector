from mamba import description, it, context, before
from expects import expect, have_length, be_above, have_key, equal, be_none

import securecscc


with description(securecscc.SysdigSecureClient) as self:
    with before.all:
        self.client = securecscc.SysdigSecureClient(securecscc.Credentials())

    with context('when retrieving events happened on last minute'):
        with before.all:
            self.events = self.client.events_happened_on_last_minute()

        with it('returns more than 0 events'):
            expect(self.events).to(have_length(be_above(0)))

        with it('event contains an id'):
            expect(self.events[0]).to(have_key('id'))

        with it('event contains the timestamp'):
            expect(self.events[0]).to(have_key('timestamp'))

    with it('retrieves a policy from its id'):
        policy_id = 3120
        policy_name = 'Disallowed SSH Connection'

        policy = self.client.find_policy_by_id(policy_id)

        expect(policy).to(equal(policy_name))

    with context('when finding a hostname from its MAC'):
        with it('returns the hostname'):
            mac = '42:01:0a:9c:00:03'
            hostname = 'gke-demo-default-pool-1af4d30b-hnbq'

            host = self.client.find_host_by_mac(mac)

            expect(host).to(equal(hostname))

        with context('and does not exist'):
            with it('returns None'):
                inexistent_mac = 'inexistent mac'

                host = self.client.find_host_by_mac(inexistent_mac)

                expect(host).to(be_none)

    with context('when finding a container image from container id'):
        with it('returns the container image'):
            container_id = 'f8dfc7daf23f'
            container_image = 'gcr.io/google-containers/prometheus-to-sd@sha256:5831390762c790b0375c202579fd41dd5f40c71950f7538adbe14b0c16f35d56'

            host = self.client.find_container_image_from_container_id(container_id)

            expect(host).to(equal(container_image))

        with context('and does not exist'):
            with it('returns None'):
                non_existent_container_id = 'inexistent container id'

                host = self.client.find_container_image_from_container_id(non_existent_container_id)

                expect(host).to(be_none)

    with context('when finding container metadata from container id'):
        with context('and metadata is found'):
            with before.all:
                container_id = '2c5f1958c499'

                self.metadata = self.client.find_container_metadata_from_container_id(container_id)

            with it('contains a container.id'):
                expect(self.metadata).to(have_key('container.id', '2c5f1958c499'))

            with it('contains a container.name'):
                expect(self.metadata).to(have_key('container.name', 'k8s_ftest_jclient-755f58fb54-58cb2_example-java-app_443ecb93-3d9e-11e8-9249-42010a9c0071_0'))

            with it('contains a container.image'):
                expect(self.metadata).to(have_key('container.image', 'sysdig/ftest@sha256:a3bdb330f385bd4bb6c34aa6e3953d2349190b7d375ca2ce5e8168ff18dfdd6d'))

            with it('contains a kubernetes.pod.name'):
                expect(self.metadata).to(have_key('kubernetes.pod.name', 'jclient-755f58fb54-58cb2'))

            with it('contains a kubernetes.deployment.name'):
                expect(self.metadata).to(have_key('kubernetes.deployment.name', 'jclient'))

            with it('contains a kubernetes.namespace.name'):
                expect(self.metadata).to(have_key('kubernetes.namespace.name', 'example-java-app'))

            with it('contains an agent.tag'):
                expect(self.metadata).to(have_key('agent.tag', 'securedev'))

        with context('and metadata is not found'):
            with it('returns None'):
                container_id = 'non existent'

                metadata = self.client.find_container_metadata_from_container_id(container_id)

                expect(metadata).to(be_none)

    with it('creates a webhook notification channel with authentication'):
        name = 'AUTOMATED_TEST'
        url = 'http://localhost:9000'
        authentication_token = 'f00Bar'

        self.client.delete_notification_channel(name)
        notification_channel = self.client.create_webhook_notification_channel(name, url, authentication_token)

        expect(notification_channel).to(have_key('name', name))
        expect(notification_channel['options']).to(have_key('url', url))
        expect(notification_channel['options']).to(have_key('additionalHeaders', {'Authorization': authentication_token}))
