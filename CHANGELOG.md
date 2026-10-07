# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 4.3.2 are described by their release commits.

## 4.5.1 - 2026-10-07

### Fixes

- Retry an answer a call cannot read, as a server_error ([`cf5e56f`](https://github.com/vpndetection-io/sdk-php/commit/cf5e56fbc92ea0efcdfe26e122abd3d61c7e8c52))
- Read a Retry-After as seconds or an HTTP date, and nothing else ([`3271dfc`](https://github.com/vpndetection-io/sdk-php/commit/3271dfcc833a5d2d58ebc285a7f8a85434fd74d5))

## 4.5.0 - 2026-10-04

### Features

- Add the authorization code sign-in, with PKCE ([`aa8cd99`](https://github.com/vpndetection-io/sdk-php/commit/aa8cd99699c5ffa5e78386fd60a5eb8c52ba6c8c))

## 4.4.3 - 2026-10-04

### Fixes

- Re-pin the spec to 2026.10.03: metadata needs no license ([`a4b48c2`](https://github.com/vpndetection-io/sdk-php/commit/a4b48c2010d12f7146311d2c342121dbf11bb273))

## 4.4.2 - 2026-09-29

### Fixes

- Recognize 26 more reserved ranges as bogons, as the API does ([`3c99a7d`](https://github.com/vpndetection-io/sdk-php/commit/3c99a7dd7a6d594966d10de0608976809cfb9046))

## 4.4.1 - 2026-09-28

### Fixes

- Judge an IPv4-mapped address as the IPv4 address it carries ([`6693753`](https://github.com/vpndetection-io/sdk-php/commit/66937539d1ab0909b35a3582f40e8d227e0158d9))

## 4.4.0 - 2026-09-27

### Features

- Re-pin the spec to 2026.09.26, adding clientIdMetadataDocumentSupported ([`e1a62ad`](https://github.com/vpndetection-io/sdk-php/commit/e1a62ad593202006f3f0ca1668a3a37d00584a56))

## 4.3.2 - 2026-09-23

### Fixes

- Bound Retry-After and the poll's sleep, refuse a timeout where set ([`4910526`](https://github.com/vpndetection-io/sdk-php/commit/4910526d042551f648ea5f0e123a1aa24a23afe6))
