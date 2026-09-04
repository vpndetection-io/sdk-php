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
