from securecscc import finding_mappers


class CreateFindingFromEvent:
    def __init__(self, settings, gcloud_client, sysdig_client):
        self._settings = settings
        self._gcloud_client = gcloud_client
        self._sysdig_client = sysdig_client

        self._sysdig_secure_finding_mapper = finding_mappers.SysdigSecureFindingMapper(self._settings, self._sysdig_client, self._gcloud_client)
        self._falco_finding_mapper = finding_mappers.FalcoFindingMapper(self._settings)

    def run(self, event):
        if self._comes_from_sysdig_secure(event):
            finding = self._sysdig_secure_finding_mapper.create_from(event)
        else:
            finding = self._falco_finding_mapper.create_from(event)

        self._gcloud_client.create_finding(self._settings.organization(),
                                           finding)

        return finding

    def _comes_from_sysdig_secure(self, event):
        return 'version' in event


class CreateCSCCNotificationChannel:
    def __init__(self, settings, sysdig_client):
        self._settings = settings
        self._sysdig_client = sysdig_client

    def run(self):
        return self._sysdig_client.create_webhook_notification_channel('Google Security Command Center',
                                                                       self._settings.webhook_url(),
                                                                       self._settings.webhook_authentication_token())
