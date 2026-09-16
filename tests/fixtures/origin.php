<?php

declare(strict_types=1);

// The router behind VPNDetection\Tests\Origin: the API's 302 and the object
// storage it points at, on one host. Started by the test, configured through the
// environment, and it appends one JSON line per request so a test can assert
// what did NOT happen.

$log = (string) getenv('ORIGIN_LOG');
$path = (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);

$headers = [];
foreach ($_SERVER as $key => $value) {
    if (str_starts_with((string) $key, 'HTTP_')) {
        $headers[strtolower(str_replace('_', '-', substr((string) $key, 5)))] = $value;
    }
}
file_put_contents(
    $log,
    json_encode(['path' => $path, 'query' => $_GET, 'headers' => $headers]) . "\n",
    FILE_APPEND,
);

// An API call that sends its headers and the start of a body, then nothing: a
// deadline that stopped the clock at the headers would never fire here.
$stall = getenv('ORIGIN_STALL_SECONDS');
if ($stall !== false) {
    header('Content-Type: application/json');
    header('Content-Length: 1024');
    echo '{"ip":';
    flush();
    sleep((int) $stall);
    exit;
}

// The same, except a byte keeps arriving every few milliseconds, so no single
// read ever waits long: only a bound on the whole response ends this call.
$trickle = getenv('ORIGIN_TRICKLE_MS');
if ($trickle !== false) {
    header('Content-Type: application/json');
    header('Content-Length: 1024');
    for ($i = 0; $i < 1024; $i++) {
        echo ' ';
        flush();
        usleep((int) $trickle * 1000);
    }
    exit;
}

if ($path === '/api/v1/database/download') {
    header('Location: http://' . $_SERVER['HTTP_HOST'] . '/blob', true, 302);
    exit;
}
if ($path !== '/blob') {
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['rc' => 'NOT_FOUND']);
    exit;
}

// Fails the first N attempts at the blob before serving it, so a test can watch
// what a retry does before any byte of the body exists.
$failFirst = (int) (getenv('ORIGIN_FAIL_FIRST') ?: '0');
$attemptFile = dirname($log) . '/blob-attempts';
$attempt = (int) (@file_get_contents($attemptFile) ?: '0');
file_put_contents($attemptFile, (string) ($attempt + 1));
if ($attempt < $failFirst) {
    http_response_code(503);
    header('Content-Type: application/xml');
    echo '<Error><Code>SlowDown</Code></Error>';
    exit;
}

$status = (int) (getenv('ORIGIN_STORAGE_STATUS') ?: '200');
if ($status !== 200) {
    http_response_code($status);
    header('Content-Type: application/xml');
    echo '<Error><Code>AccessDenied</Code></Error>';
    exit;
}

$total = (int) (getenv('ORIGIN_BLOB_BYTES') ?: '0');
$dieAfter = getenv('ORIGIN_DIE_AFTER');
header('Content-Type: application/octet-stream');
header('Content-Length: ' . $total);

// Promising more than it delivers and then dropping the connection is the only
// way to reach the half-written destination: a refusal fails before a byte of it
// exists.
$deliver = $dieAfter === false ? $total : (int) $dieAfter;
$chunk = str_repeat('a', 1024 * 1024);
for ($sent = 0; $sent < $deliver; $sent += strlen($chunk)) {
    echo substr($chunk, 0, min(strlen($chunk), $deliver - $sent));
    flush();
}
