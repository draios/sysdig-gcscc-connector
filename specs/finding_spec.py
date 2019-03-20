from mamba import description, it, context
from expects import expect, have_length, be_above, have_key, equal, be_none


from google.protobuf import struct_pb2

import securecscc


with description(securecscc.Finding) as self:
    # This was detected as a regression
    with context('when serializing to Google Cloud Security Center'):
        with it('includes rule type'):
            finding = self.finding()

            serialized = finding.to_google_cloud_security_center()

            expect(serialized['source_properties'])\
                .to(have_key('rule_type',
                             struct_pb2.Value(string_value=finding.rule_type)))

        with it('includes container_name from container_metadata'):
            finding = self.finding()

            serialized = finding.to_google_cloud_security_center()

            expect(serialized['source_properties'])\
                .to(have_key('container_name',
                             struct_pb2.Value(string_value=finding.container_metadata['container.name'])))

        def finding(self):
            return securecscc.Finding(**{
                'finding_id': '656703705613148160',
                'source': 'organizations/707341064895/sources/4472002082094996606',
                'category': 'Terminal shell in container',
                'event_time': 1553098717,
                'url': 'https://secure.sysdig.com/#/events/f:1553098657,t:1553098777/*/*?viewAs=list',
                'resource_name': '//compute.googleapis.com/projects/sysdig-204815/zones/europe-west3-a/instances/7045420945307206367',
                'priority': None,
                'summary': 'A shell was spawned in a container with an attached terminal (user=root k8s_nginx_nginx-78f5d695bd-vk44n_default_ce1ac962-4994-11e9-8881-42010a9c01af_0 (id=1e4dcb0c1ce5) shell=bash parent=runc:[0:PARENT] cmdline=bash terminal=34817)',
                'container_id': None,
                'container_name': None,
                'kubernetes_pod_name': None,
                'severity': 4, 'rule_type': 'RULE_TYPE_FALCO',
                'container_metadata': {
                    'container.id': '1e4dcb0c1ce5',
                    'container.name': 'k8s_nginx_nginx-78f5d695bd-vk44n_default_ce1ac962-4994-11e9-8881-42010a9c01af_0',
                    'container.image': 'nginx@sha256:7734a210432278817f8097acf2f72d20e2ccc7402a0509810c44b3a8bfe0094a',
                    'kubernetes.pod.name': 'nginx-78f5d695bd-vk44n',
                    'kubernetes.deployment.name': 'nginx',
                    'kubernetes.namespace.name': 'default',
                    'agent.tag': 'helm-gke'
                }
            })
