class CreateFindingFromEvent:
    def __init__(self, settings, gcloud_client, origin):
        self._settings = settings
        self._gcloud_client = gcloud_client
        self._origin = origin

    def run(self, event):
        finding = self._origin.create_from(event)
        self._gcloud_client.create_finding(finding)

        return finding


class CreateCSCCNotificationChannel:
    def __init__(self, settings, sysdig_client):
        self._settings = settings
        self._sysdig_client = sysdig_client

    def run(self):
        return self._sysdig_client.create_webhook_notification_channel('Google Security Command Center',
                                                                       self._settings.webhook_url(),
                                                                       self._settings.webhook_authentication_token())
