from functools import lru_cache

from securecscc.actions import CreateFindingFromEvent, CreateCSCCNotificationChannel
from securecscc.infrastructure import SysdigSecureClient, GoogleCloudClient
from securecscc.settings import Settings
from securecscc.credentials import Credentials
from securecscc import origins


class ApplicationFactory(object):
    @lru_cache(maxsize=1)
    def create_finding_from_sysdig_secure_event_action(self):
        return CreateFindingFromEvent(self.settings(),
                                      self.google_cloud_client(),
                                      self._sysdig_secure())

    @lru_cache(maxsize=1)
    def create_finding_from_falco_alarm_action(self):
        return CreateFindingFromEvent(self.settings(),
                                      self.google_cloud_client(),
                                      self._falco())

    @lru_cache(maxsize=1)
    def create_cscc_notification_channel_action(self):
        return CreateCSCCNotificationChannel(self.settings(),
                                             self.sysdig_secure_client())

    @lru_cache(maxsize=1)
    def sysdig_secure_client(self):
        return SysdigSecureClient(self._credentials())

    @lru_cache(maxsize=1)
    def google_cloud_client(self):
        return GoogleCloudClient(self._credentials())

    @lru_cache(maxsize=1)
    def settings(self):
        return Settings()

    @lru_cache(maxsize=1)
    def _falco(self):
        return origins.Falco(self.settings())

    @lru_cache(maxsize=1)
    def _sysdig_secure(self):
        return origins.SysdigSecure(self.settings(),
                                    self.sysdig_secure_client(),
                                    self.google_cloud_client())

    @lru_cache(maxsize=1)
    def _credentials(self):
        return Credentials()
