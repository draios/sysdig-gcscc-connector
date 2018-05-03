class CreateFindingFromEvent:
    def __init__(self, settings, gcloud_client, sysdig_client):
        self._settings = settings
        self._gcloud_client = gcloud_client
        self._sysdig_client = sysdig_client

    def run(self, event):
        finding = self._build_finding_from(event)
        self._gcloud_client.create_finding(self._settings.organization(),
                                           finding)

        return finding

    def _build_finding_from(self, event):
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


class CreateCSCCNotificationChannel:
    def __init__(self, settings, sysdig_client):
        self._settings = settings
        self._sysdig_client = sysdig_client

    def run(self):
        return self._sysdig_client.create_webhook_notification_channel('Google Security Command Center',
                                                                       self._settings.webhook_url(),
                                                                       self._settings.webhook_authentication_token())
