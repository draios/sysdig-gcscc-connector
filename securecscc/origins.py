import uuid


class Finding(object):
    SOURCE_FALCO = 'Falco'
    SOURCE_SYSDIG_SECURE = 'SysdigSecure'

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


class Falco(object):
    def __init__(self, settings):
        self._settings = settings

    def create_from(self, event):
        return Finding(
            source=Finding.SOURCE_FALCO,
            category=event['rule'],
            event_time=int(event['output_fields']['evt.time']/1000000000),
            #resource_name=self._sysdig_client.project()
            priority=event['priority'],
            summary=event['output'].replace(event['priority'], '')[19:].strip(),
            container_id=event['output_fields']['container.id'],
            container_name=event['output_fields'].get('container.name'),
            kubernetes_pod_name=event['output_fields'].get('k8s.pod.name')
        )


class SysdigSecure(object):
    def __init__(self, settings, sysdig_client, gcloud_client):
        self._settings = settings
        self._sysdig_client = sysdig_client
        self._gcloud_client = gcloud_client

    def create_from(self, event):
        event_time = int(event['timestamp']/1000000)

        return Finding(
            finding_id=event['id'],
            source=Finding.SOURCE_SYSDIG_SECURE,
            category=self._sysdig_client.find_policy_by_id(event['policyId']),
            event_time=event_time,
            #resource_name=self._sysdig_client.project()
            url=self._sysdig_url(event_time),
            summary=event['output'],
            severity=event['severity'],
            rule_type=event['ruleType'],
            container_metadata=self._container_metadata(event)
        )

    def _sysdig_url(self, event_time):
        return "{url_prefix}/#/events/f:{f},t:{t}/*/*?viewAs=list"\
            .format(url_prefix=self._settings.sysdig_url_prefix(),
                    f=event_time - 60,
                    t=event_time + 60)

    def _container_metadata(self, event):
        if 'containerId' not in event:
            return {}

        return self._sysdig_client.find_container_metadata_from_container_id(event['containerId'])

    #def _asset_ids(self, event):
    #    container_image = self._container_image(event)
    #    if container_image is not None:
    #        return [container_image]

    #    instance_id = self._instance_id(event)
    #    if instance_id is not None:
    #        return [instance_id]

    #    return [self._settings.organization()]

    #def _container_image(self, event):
    #    if 'containerId' not in event:
    #        return None

    #    container_image = self._sysdig_client\
    #        .find_container_image_from_container_id(event['containerId'])

    #    if container_image is not None and container_image.startswith('gcr.io'):
    #        return container_image

    #    return None

    #def _instance_id(self, event):
    #    hostname = self._sysdig_client.find_host_by_mac(event['hostMac'])
    #    if hostname is not None:
    #        instance_id = self._gcloud_client\
    #            .get_instance_id_from_hostname(self._settings.project(),
    #                                           self._settings.zone(),
    #                                           hostname)

    #        if instance_id is not None:
    #            return '{}/instance/{}'.format(self._settings.project(),
    #                                           instance_id)

    #    return None

