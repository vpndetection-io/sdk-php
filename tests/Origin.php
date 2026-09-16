<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use PHPUnit\Framework\Assert;
use RuntimeException;
use VPNDetection\Client;
use VPNDetection\ErrorKind;
use VPNDetection\Options;
use VPNDetection\VPNDetectionException;

/**
 * A real HTTP origin serving the download 302 and the object storage behind it,
 * or an API call that stalls part way through its body.
 *
 * The download methods exist to answer what a transport does with a redirect and
 * with a body too large to hold, and a stubbed handler answers neither: Guzzle
 * routes a streamed request to a different handler entirely, so a canned
 * response would exercise none of the code that matters.
 */
final class Origin
{
    public readonly string $baseUrl;

    /** @var resource */
    private $process;

    private readonly string $logPath;

    /**
     * @param array{blobBytes?: int, storageStatus?: int, dieAfterBytes?: int, failFirst?: int,
     *     stallSeconds?: int, trickleMs?: int} $options
     */
    public function __construct(array $options = [])
    {
        $port = self::freePort();
        $dir = sys_get_temp_dir() . '/vpndetection-origin-' . bin2hex(random_bytes(6));
        mkdir($dir);
        $this->logPath = $dir . '/requests.jsonl';
        touch($this->logPath);
        $this->baseUrl = "http://127.0.0.1:{$port}";

        $env = [
            'ORIGIN_LOG' => $this->logPath,
            'ORIGIN_BLOB_BYTES' => (string) ($options['blobBytes'] ?? 0),
            'ORIGIN_STORAGE_STATUS' => (string) ($options['storageStatus'] ?? 200),
            'ORIGIN_FAIL_FIRST' => (string) ($options['failFirst'] ?? 0),
        ];
        if (isset($options['dieAfterBytes'])) {
            $env['ORIGIN_DIE_AFTER'] = (string) $options['dieAfterBytes'];
        }
        if (isset($options['stallSeconds'])) {
            $env['ORIGIN_STALL_SECONDS'] = (string) $options['stallSeconds'];
        }
        if (isset($options['trickleMs'])) {
            $env['ORIGIN_TRICKLE_MS'] = (string) $options['trickleMs'];
        }

        $command = [
            PHP_BINARY, '-n', '-d', 'zlib.output_compression=0',
            '-S', "127.0.0.1:{$port}", '-t', $dir, __DIR__ . '/fixtures/origin.php',
        ];
        $pipes = [];
        $process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, $dir, $env);
        if ($process === false) {
            throw new RuntimeException('could not start the origin');
        }
        $this->process = $process;
        self::waitForPort($port);
    }

    /**
     * One origin per call, because the built-in server serves one request at a
     * time. It is slower than either bound, so a regression fails the timing
     * assertion instead of hanging the suite.
     *
     * @param array{stallSeconds?: int, trickleMs?: int} $body
     * @param callable(Client): mixed $call
     */
    public static function assertTimesOut(
        array $body,
        float $clientTimeout,
        callable $call,
        string $name,
    ): void
    {
        $origin = new Origin($body);
        $client = new Client(
            new Options(baseUrl: $origin->baseUrl, cache: false, retries: 0, timeout: $clientTimeout),
        );
        $started = microtime(true);
        try {
            $answer = $call($client);
        } catch (VPNDetectionException $e) {
            $answer = $e;
        } finally {
            $elapsed = microtime(true) - $started;
            $origin->stop();
        }

        Assert::assertInstanceOf(VPNDetectionException::class, $answer, "{$name} should have timed out");
        Assert::assertSame(ErrorKind::Network, $answer->kind, $name);
        Assert::assertTrue($answer->isRetryable(), "{$name}: a timeout is worth another attempt");
        Assert::assertGreaterThanOrEqual(0.2, $elapsed, "{$name} failed without waiting");
        Assert::assertLessThan(1.5, $elapsed, "{$name} waited past its 0.25s bound");
    }

    public function stop(): void
    {
        proc_terminate($this->process);
        proc_close($this->process);
    }

    /**
     * Every request the origin saw, in order.
     *
     * @return list<array{path: string, query: array<string, string>, headers: array<string, string>}>
     */
    public function requests(): array
    {
        $lines = array_filter(explode("\n", (string) file_get_contents($this->logPath)), strlen(...));
        return array_map(
            static fn (string $line): array => json_decode($line, true, 512, JSON_THROW_ON_ERROR),
            array_values($lines),
        );
    }

    /** @return list<array{path: string, query: array<string, string>, headers: array<string, string>}> */
    public function requestsTo(string $path): array
    {
        return array_values(array_filter($this->requests(), static fn (array $r): bool => $r['path'] === $path));
    }

    private static function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        if ($socket === false) {
            throw new RuntimeException("could not reserve a port: {$error}");
        }
        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);
        return (int) substr($name, strrpos($name, ':') + 1);
    }

    private static function waitForPort(int $port): void
    {
        for ($i = 0; $i < 200; $i++) {
            $probe = @fsockopen('127.0.0.1', $port, $errno, $error, 0.1);
            if ($probe !== false) {
                fclose($probe);
                return;
            }
            usleep(25_000);
        }
        throw new RuntimeException("the origin never accepted a connection on port {$port}");
    }
}
