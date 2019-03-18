import uuid

from google.cloud import securitycenter
from google.protobuf import timestamp_pb2, struct_pb2


class Finding(object):
    def __init__(self, **kwargs):
        self.finding_id = kwargs.get('finding_id', uuid.uuid4().hex)
        self.source = kwargs['source']
        self.category = kwargs['category']
        self.event_time = kwargs['event_time']

        self.url = kwargs.get('url')
        self.resource_name = kwargs.get('resource_name')

        # Properties not present in all findings
        self.priority = kwargs.get('priority')
        self.summary = kwargs.get('summary')
        self.container_id = kwargs.get('container_id')
        self.container_name = kwargs.get('container_name')
        self.kubernetes_pod_name = kwargs.get('kubernetes_pod_name')
        self.severity = kwargs.get('severity')
        self.rule_type = kwargs.get('rule_type')
        self.container_metadata = kwargs.get('container_metadata', {})

    def to_google_cloud_security_center(self):
        return {
            'category': self.category,
            'state': securitycenter.enums.Finding.State.ACTIVE,
            'resource_name': self.resource_name,
            'event_time': timestamp_pb2.Timestamp(seconds=self.event_time),
            'external_uri': self.url,
            'source_properties': {
                #self._replace_dots(key): struct_pb2.Value(string_value=str(value)) for key, value in self.get('properties', {}).items()
            }
        }

    def _replace_dots(self, value):
        return value.replace('.', '_')
