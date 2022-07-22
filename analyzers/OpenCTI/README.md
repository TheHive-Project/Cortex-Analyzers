[OpenCTI](https://www.opencti.io/en/) is an open cyber threat intelligence platform which aims at providing a powerful knowledge management database with an enforced schema especially tailored for cyber threat intelligence and cyber operations and based on STIX 2.

The analyzer comes in only one flavor to look for an observable in the platform.
The analyzer comes in two flavors to search for an observable in the platform:

- OpenCTI_**SearchExactObservable**: returns an exact match only
- OpenCTI_**SearchObservables**: returns all observables containing the input data

#### Requirements

The OpenCTI analyzer requires you to have access to one or several [OpenCTI](https://www.opencti.io/en/)
 instances. You can also deploy your own instance.
 instances in version 4. You can also deploy your own instance.

Three parameters are required for each instance to make the analyzer work:

- `url` : URL of the instance, e.g. "https://demo.opencti.io"
