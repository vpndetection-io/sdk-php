<?php

declare(strict_types=1);

// Runs the integration suite against the package as PUBLISHED on Packagist,
// which is the one thing the unit suite cannot check: it tests this working
// tree, so it stays green through a `.gitattributes` that exports no `src`, an
// autoload map a consumer cannot resolve, or a tag that never landed.
//
//   php scripts/run.php            # from integration/, with composer on PATH
//   ./scripts/run.sh               # the same thing in docker, for a box with no PHP
//
// Two conditions make the run meaningless rather than failing, and each one
// skips with a reason instead:
//
//   1. Nothing on Packagist satisfies the declared constraint. Before the first
//      release there is no published artifact to test.
//   2. A tier's staging key is missing. The unauthenticated tests still run, and
//      each tier without a key skips from inside the suite, so the skip and its
//      reason land in the PHPUnit output rather than in this script's preamble.

use VPNDetection\Integration\Tiers;

const PACKAGE = 'vpndetection/vpndetection';

// Required directly: the runner reads the tier table BEFORE composer has put an
// autoloader on disk.
require __DIR__ . '/../lib/Tiers.php';

try {
    main();
} catch (Throwable $e) {
    fwrite(STDERR, "==> FAILED: {$e->getMessage()}\n");
    exit(1);
}

function main(): void
{
    $dir = dirname(__DIR__);
    $constraint = (string) readJson($dir . '/composer.json')['require'][PACKAGE];

    $versions = publishedVersions($dir, $constraint);
    if ($versions === null) {
        skip(PACKAGE . "@{$constraint} is not on Packagist, so there is no published artifact to test");
        return;
    }
    echo '==> ' . PACKAGE . "@{$constraint} matches published " . implode(', ', $versions) . "\n";

    // Empty counts as absent: Actions interpolates a secret that does not exist
    // to an empty string, and an empty key is sent as no key at all.
    $withKey = tiersWhere(static fn (array $rung): bool => Tiers::skipFor($rung) === null);
    $absent = tiersWhere(static fn (array $rung): bool => Tiers::skipFor($rung) !== null);
    echo '==> tiers with a key: ' . implode(', ', $withKey) . "\n";
    if ($absent !== []) {
        notice('no staging key for ' . implode(', ', $absent) . ': those tiers are skipped');
    }

    // Both removed so every run resolves the constraint afresh. A kept lock file
    // would pin whatever the first run happened to pick, and the daily run would
    // stop noticing new releases.
    removeTree($dir . '/vendor');
    @unlink($dir . '/composer.lock');
    run(composer(), ['update', '--no-interaction', '--no-progress', '--no-audit'], $dir);

    assertInstalledFromPackagist($dir, $versions);
    run(PHP_BINARY, [$dir . '/vendor/bin/phpunit', '--colors=never'], $dir);
}

/**
 * `composer show <package> <constraint>` is composer's own resolver, so the
 * constraint is read exactly as `composer update` will read it. A package that
 * does not exist and a constraint nothing satisfies both answer "not found", and
 * both mean the same thing here: there is nothing published to test yet.
 *
 * @return list<string>|null
 */
function publishedVersions(string $dir, string $constraint): ?array
{
    $result = capture(composer(), ['show', PACKAGE, $constraint, '--available', '--format=json'], $dir);
    if ($result['status'] !== 0) {
        if (str_contains($result['stderr'], 'not found')) {
            return null;
        }
        throw new RuntimeException("composer show failed: {$result['stderr']}");
    }
    $versions = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR)['versions'] ?? [];
    return $versions === [] ? null : array_values($versions);
}

/**
 * The suite is worthless if composer handed it the working tree, and that
 * failure is silent: every test passes, against the wrong code. A path
 * repository symlinks by default, so the link is the first thing to rule out.
 *
 * @param list<string> $versions
 */
function assertInstalledFromPackagist(string $dir, array $versions): void
{
    $installed = $dir . '/vendor/' . PACKAGE;
    if (is_link($installed)) {
        throw new RuntimeException("{$installed} is a symlink, so the tests would run against local source");
    }
    $entry = null;
    foreach (readJson($dir . '/vendor/composer/installed.json')['packages'] as $package) {
        if ($package['name'] === PACKAGE) {
            $entry = $package;
        }
    }
    if ($entry === null) {
        throw new RuntimeException(PACKAGE . ' is not in the installed set at all');
    }
    $url = (string) ($entry['dist']['url'] ?? '');
    if (($entry['dist']['type'] ?? '') === 'path' || !str_starts_with($url, 'https://')) {
        throw new RuntimeException(PACKAGE . ' was not resolved from a registry: ' . json_encode($entry['dist']));
    }
    if (!in_array(release($entry['version']), array_map(release(...), $versions), true)) {
        throw new RuntimeException(
            "installed {$entry['version']}, which is not one of " . implode(', ', $versions),
        );
    }
    echo '==> installed ' . PACKAGE . "@{$entry['version']} from {$url}\n";
}

// A tag may or may not carry a leading v, and composer reports it as tagged.
function release(string $version): string
{
    return ltrim($version, 'v');
}

function composer(): string
{
    return (string) (getenv('COMPOSER_BIN') ?: 'composer');
}

/** @param list<string> $args */
function run(string $command, array $args, string $cwd): void
{
    echo '==> ' . basename($command) . ' ' . implode(' ', $args) . "\n";
    $process = proc_open([$command, ...$args], [STDIN, STDOUT, STDERR], $pipes, $cwd);
    if ($process === false || proc_close($process) !== 0) {
        throw new RuntimeException(basename($command) . ' ' . implode(' ', $args) . ' failed');
    }
}

/**
 * @param list<string> $args
 * @return array{status: int, stdout: string, stderr: string}
 */
function capture(string $command, array $args, string $cwd): array
{
    $spec = [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']];
    $process = proc_open([$command, ...$args], $spec, $pipes, $cwd);
    if ($process === false) {
        throw new RuntimeException("could not run {$command}");
    }
    fclose($pipes[0]);
    $stdout = (string) stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return ['status' => proc_close($process), 'stdout' => $stdout, 'stderr' => $stderr];
}

/** @param callable(array{tier: string, secret: string|null, widens: bool}): bool $predicate */
function tiersWhere(callable $predicate): array
{
    return array_column(array_filter(Tiers::RUNGS, $predicate), 'tier');
}

/** @return array<string, mixed> */
function readJson(string $path): array
{
    return json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
}

function removeTree(string $path): void
{
    if (!is_dir($path)) {
        return;
    }
    run('rm', ['-rf', $path], dirname($path));
}

function skip(string $reason): void
{
    echo "==> SKIPPED: {$reason}\n";
    notice("Integration suite skipped: {$reason}");
}

// Surfaced on the workflow run itself, so a skip is visible without opening the
// log and reading to the end of it.
function notice(string $message): void
{
    if (getenv('GITHUB_ACTIONS') === 'true') {
        echo "::notice title=Integration::{$message}\n";
    }
}
