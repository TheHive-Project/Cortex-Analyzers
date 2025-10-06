[EclecticIQ](https://www.eclecticiq.com/) is a cyber threat intelligence platform which provides aggregation and analysis capabilities for threat intelligence data and integration with organization assets.

The analyzer comes in one flavor to look for an observable in the platform and return any parent entities and their context.

- EclecticIQ\_**SearchObservable**: returns entity data for a specific observable

#### Requirements

The EclecticIQ analyzer requires you to have access to an [EclecticIQ Intelligence Center](https://www.eclecticiq.com/) instance.

Three parameters are required for each instance to make the analyzer work:

- `url` : URL of the instance, e.g. "https://intel-platform.local"
- `key` : API Key for a user of the EclecticIQ Intelligence Center instance
