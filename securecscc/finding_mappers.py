import uuid


class FalcoFindingMapper:
    def __init__(self, settings):
        self._settings = settings

    def create_from(self, event):
        event_time = int(event['output_fields']['evt.time']/1000000000)

        return {
            "id": str(uuid.uuid4()),
            "source_id": self._settings.source_id(),
            "category": event['rule'],
            "event_time": event_time,
            "url": None,
            "asset_ids": [self._settings.organization()],
            "properties": {
                "priority": event['priority'],
                "summary": event['output'].replace(event['priority'], '')[19:].strip()
            }
        }


class SysdigSecureFindingMapper:
    def __init__(self, settings, sysdig_client, gcloud_client):
        self._settings = settings
        self._sysdig_client = sysdig_client
        self._gcloud_client = gcloud_client

    def create_from(self, event):
        event_time = int(event['timestamp']/1000000)

        return {
            "id": event['id'],
            "category": self._sysdig_client.find_policy_by_id(event['policyId']),
            "asset_ids": self._asset_ids(event),
            "source_id": self._settings.source_id(),
            "event_time": event_time,
            "url": self._sysdig_url(event_time),
            'properties': self._properties(event),
        }

    def _asset_ids(self, event):
        container_image = self._container_image(event)
        if container_image is not None:
            return [container_image]

        instance_id = self._instance_id(event)
        if instance_id is not None:
            return [instance_id]

        return [self._settings.organization()]

    def _container_image(self, event):
        if 'containerId' not in event:
            return None

        container_image = self._sysdig_client\
            .find_container_image_from_container_id(event['containerId'])

        if container_image is not None and container_image.startswith('gcr.io'):
            return container_image

        return None

    def _instance_id(self, event):
        hostname = self._sysdig_client.find_host_by_mac(event['hostMac'])
        if hostname is not None:
            instance_id = self._gcloud_client\
                .get_instance_id_from_hostname(self._settings.project(),
                                               self._settings.zone(),
                                               hostname)

            if instance_id is not None:
                return '{}/instance/{}'.format(self._settings.project(),
                                               instance_id)

        return None

    def _sysdig_url(self, event_time):
        return "{url_prefix}/#/events/f:{f},t:{t}/*/*?viewAs=list"\
            .format(url_prefix=self._settings.sysdig_url_prefix(),
                    f=event_time - 60,
                    t=event_time + 60)

    def _properties(self, event):
        properties = {
            'summary': event['output'],
            'severity': event['severity'],
            'rule.type': event['ruleType']
        }

        if 'containerId' not in event:
            return properties

        metadata = self._sysdig_client.find_container_metadata_from_container_id(event['containerId'])
        if metadata is not None:
            properties.update(metadata)

        return properties
