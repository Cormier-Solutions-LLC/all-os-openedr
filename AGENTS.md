## Code Review Rules

- Reject any change that lets a contributor-controlled event, workflow or ref run code on `cormier-runners` before the maintainer approves the exact code.
- Flag releases missing a version in an asset name, the CASL notice, or separate redistribution clearance for binaries with excluded SDK dependencies.
- Keep Wazuh and OpenSearch credentials in operator-managed secrets. Require TLS verification and limit the OpenSearch role to the integration's indices.
