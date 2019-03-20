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
            'state': securitycenter.enums.Finding.State.ACTIVE,
            'category': self.category,
            'event_time': timestamp_pb2.Timestamp(seconds=self.event_time),
            'external_uri': self.url,
            'resource_name': self.resource_name,
            'source_properties': self._source_properties()
        }

    def _source_properties(self):
        source_properties = {}
        properties = ['priority', 'summary', 'container_id', 'container_name',
                      'kubernetes_pod_name', 'severity', 'rule_type']

        for name in properties:
            value = getattr(self, name)
            if value is not None:
                source_properties[name] = \
                    struct_pb2.Value(string_value=str(value))

        for key, value in self.container_metadata.items():
            source_properties[name] = struct_pb2.Value(string_value=str(value))

        return source_properties

    def _replace_dots(self, value):
        return value.replace('.', '_')

    def to_dict(self):
        return self.__dict__
