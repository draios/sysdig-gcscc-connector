from mamba import description, it
from expects import expect
from doublex import Spy
from doublex_expects import have_been_called_with

import securecscc


with description(securecscc.CreateCSCCNotificationChannel) as self:
    with it('creates a notification channel in Sysdig Secure'):
        settings = securecscc.Settings()
        sysdig_client = Spy(securecscc.SysdigSecureClient)
        action = securecscc.CreateCSCCNotificationChannel(sysdig_client)
        webhook_url = 'irrelevant webhook url'
        webhook_authentication_token = 'irrelevant webhook authentication token'

        action.run(webhook_url, webhook_authentication_token)

        expect(sysdig_client.create_webhook_notification_channel).\
            to(have_been_called_with('Google Security Command Center',
                                     webhook_url,
                                     webhook_authentication_token))
