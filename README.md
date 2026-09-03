# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="24"/>](https://vpndetection.io/) VPNDetection PHP Client Library

[![Packagist](https://img.shields.io/packagist/v/vpndetection/vpndetection.svg)](https://packagist.org/packages/vpndetection/vpndetection)
[![license](https://img.shields.io/packagist/l/vpndetection/vpndetection.svg)](LICENSE)

The official PHP client library for the [VPNDetection](https://vpndetection.io) API.

The library helps you query VPNDetection's APIs for anonymity detection including VPNs, residential proxies, Tor nodes, hosting servers, CDNs, relays and more.

## Getting Started

```bash
composer require vpndetection/vpndetection
```

Requires PHP 8.1 or newer. Everything is typed, and the tier-gated fields are nullable so an absent answer never reads as a false one.

## Usage

**No API key needed to start.** The free tier answers `ip` and `is_vpn`, and allows 1000 requests per day per source address.

```php
use VPNDetection\Client;

$client = new Client();

$result = $client->lookup('45.83.91.1');
echo $result->isVpn ? 'yes' : 'no';   // yes
```

### With an API key

An API key raises your quota, and raises your features on a paid plan. Create one in the [console](https://app.vpndetection.io), then pass it in:

```php
use VPNDetection\Client;
use VPNDetection\Options;

$client = new Client(new Options(apiKey: getenv('VPNDETECTION_API_KEY')));

$result = $client->lookup('45.83.91.1');
$result->isVpn;             // true
$result->vpn->provider;     // 'mullvad'
$result->isHosting;         // true
$result->hosting->provider; // 'M247'
```

A field your plan does not include is `null`, which is not the same answer as `false`: `null` means "not in your plan", `false` means "checked, and no". Use `??` when you only care whether the address is flagged:

```php
if ($result->isHosting ?? false) {
    // ...
}
```

The same distinction applies to the detail objects. An object that is present but `isEmpty()` means the flag above it is false; a `null` one means your plan does not include it at all.

### Batch lookup

You can do batch lookups with a list, which parallelizes requests for you efficiently:

```php
use VPNDetection\VPNDetectionException;

$results = $client->lookupBatch(['45.83.91.1', '8.8.8.8', '1.1.1.1']);

foreach ($results as $ip => $result) {
    if ($result instanceof VPNDetectionException) {
        echo "{$ip}: {$result->getMessage()}\n";
        continue;
    }
    echo "{$ip}: ", $result->isVpn ? 'vpn' : 'clean', "\n";
}
```

Results are keyed by address, so duplicates in your list collapse into a single request and one address failing never loses the rest.

Concurrency and other variables are configurable per-call:

```php
$results = $client->lookupBatch($manyIps, ['concurrency' => 32, 'retries' => 4]);
```

### Caching

Answers are cached by default, so repeat lookups of the same address are free:

```php
$client = new Client();

$result = $client->lookup('45.83.91.1');
$result->isVpn;    // true, API request

$result2 = $client->lookup('45.83.91.1');
$result2->isVpn;   // true, no API request, result was cached
```

You can change the default cache variables (max size, TTL in seconds, etc) on initialization, or even disable it:

```php
$client = new Client(new Options(cacheMaxSize: 50_000, cacheTtlSeconds: 6 * 60 * 60));
$clientNoCache = new Client(new Options(cache: false));
```

The cache lives on the client instance, so how much it buys you depends on how long that instance lives. A worker, a queue consumer or a long-running server gets the full benefit; a classic one-request-per-process setup starts with an empty cache every time, and there a batch lookup is what saves you round trips.

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```php
$result = $client->lookup('192.168.1.1');
$result->isBogon;   // true, this answer was computed rather than served
$result->isVpn;     // false
```

The check is available on the client, which is handy when your inputs are addresses anyway:

```php
$client->isBogon('10.0.0.1');   // true
$client->isBogon('8.8.8.8');    // false
```

It is also callable on its own, if you want it without a client:

```php
use VPNDetection\Bogon;

Bogon::isBogon('10.0.0.1');   // true
```

### Errors

Failures throw a `VPNDetectionException` carrying a `kind` and a `isRetryable()` flag:

```php
use VPNDetection\VPNDetectionException;

try {
    $client->lookup('1.1.1.1');
} catch (VPNDetectionException $err) {
    echo $err->kind->value, ' ', $err->isRetryable() ? 'retryable' : 'final', "\n";
}
```

`kind` is one of `bad_request`, `unauthorized`, `forbidden`, `rate_limited`, `quota_exceeded`, `server_error` or `network`.

Note that `rate_limited` and `quota_exceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

### Database downloads

If your key carries the `db.download` scope, the licensed datasets are available through `$client->database`:

```php
$datasets = $client->database->list();
$url = $client->database->downloadUrl('vpn_ip_extended_v1', 'mmdb');
```

`downloadUrl` returns a time-limited link rather than the bytes, so you choose how to transfer a file that can run to gigabytes.

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="96"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
