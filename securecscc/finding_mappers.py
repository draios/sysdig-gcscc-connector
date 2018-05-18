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
