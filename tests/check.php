<?php

/**
 * @file
 * Runs the taint fixtures and checks them against their annotations.
 *
 * Each fixture line may end with one of:
 *   // expect: TaintedHtml, TaintedSql   these issue types must be reported here
 *   // expect: none                      nothing may be reported here
 *   // known-false-positive: TaintedHtml reported today, but wrong (documented)
 *   // known-false-negative: TaintedSql  a real flow Psalm does not report today
 *
 * The two "known" forms document current limits; each fails as soon as the
 * behaviour changes, so a fix is noticed and the annotation updated.
 *
 * Any reported taint issue on a line with no annotation also fails, so a new
 * false positive cannot slip in unnoticed.
 *
 * Then a parity check: every taint issue plain Psalm (no plugin) reports in
 * tests/fixtures/builtins.php must still be reported with the plugin. Stubs
 * that redeclare PHP built-ins can silently delete Psalm's own sinks; 1.0.0
 * lost every shell-execution sink that way.
 *
 * Usage: php tests/check.php   (or: composer test)
 */

declare(strict_types=1);

$root = dirname(__DIR__);
$psalm = $root . '/vendor/bin/psalm';
if (!is_file($psalm)) {
  fwrite(STDERR, "Run composer install first.\n");
  exit(2);
}

/**
 * Runs Psalm taint analysis and returns reported issue types per file:line.
 *
 * @return array<string, list<string>>
 */
function taint_issues(string $psalm, string $config, string $cwd): array {
  $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($psalm)
    . ' -c ' . escapeshellarg($config)
    . ' --taint-analysis --no-cache --no-progress --output-format=json';
  $errFile = tempnam(sys_get_temp_dir(), 'psalm-err-');
  $json = shell_exec('cd ' . escapeshellarg($cwd) . ' && ' . $cmd . ' 2>' . escapeshellarg($errFile));
  $stderr = (string) @file_get_contents($errFile);
  @unlink($errFile);
  $issues = json_decode((string) $json, TRUE);
  if (!is_array($issues)) {
    fwrite(STDERR, "Psalm did not produce JSON.\nstdout: " . substr((string) $json, 0, 2000) . "\nstderr: " . substr($stderr, 0, 4000) . "\n");
    exit(2);
  }
  $found = [];
  foreach ($issues as $issue) {
    if (str_starts_with((string) $issue['type'], 'Tainted')) {
      $found[basename((string) $issue['file_path']) . ':' . $issue['line_from']][] = (string) $issue['type'];
    }
  }
  return $found;
}

$found = taint_issues($psalm, $root . '/psalm.xml', $root);
$fail = 0;
$checked = 0;
$knownFalsePositives = 0;
$knownFalseNegatives = 0;

$fixtures = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/tests/fixtures', FilesystemIterator::SKIP_DOTS));
foreach ($fixtures as $fixture) {
  if (!preg_match('/\\.(php|module|inc)$/', (string) $fixture)) {
    continue;
  }
  $file = basename((string) $fixture);
  foreach (file((string) $fixture) as $index => $line) {
    $key = $file . ':' . ($index + 1);
    $got = array_values(array_unique($found[$key] ?? []));
    unset($found[$key]);
    if (preg_match('#//\s*(expect|known-false-positive|known-false-negative):\s*(.+)$#', $line, $m) !== 1) {
      continue;
    }
    $checked++;
    $want = trim($m[2]);
    if ($m[1] === 'known-false-positive') {
      $knownFalsePositives++;
    }
    $types = array_map('trim', explode(',', $want));
    if ($m[1] === 'known-false-negative') {
      $knownFalseNegatives++;
      $ok = array_intersect($types, $got) === [];
    }
    else {
      $ok = $want === 'none' ? $got === [] : array_diff($types, $got) === [];
    }
    if (!$ok) {
      $fail++;
      printf("FAIL %s  expected %s, got %s\n", $key, $want, $got === [] ? 'nothing' : implode(', ', $got));
    }
  }
}
// Anything left was reported on a line with no annotation.
foreach ($found as $key => $types) {
  $fail++;
  printf("FAIL %s  unexpected %s (no annotation on this line)\n", $key, implode(', ', array_unique($types)));
}

// Parity: the plugin must never lose a built-in sink that plain Psalm reports.
$plainConfig = tempnam(sys_get_temp_dir(), 'psalm-plain-') . '.xml';
file_put_contents($plainConfig, '<?xml version="1.0"?>'
  . '<psalm errorLevel="8" allowMissingFiles="true" xmlns="https://getpsalm.org/schema/config">'
  . '<projectFiles><file name="' . $root . '/tests/fixtures/builtins.php" /></projectFiles></psalm>');
$plain = taint_issues($psalm, $plainConfig, $root);
@unlink($plainConfig);
$withPlugin = taint_issues($psalm, $root . '/psalm.xml', $root);
$lost = 0;
foreach ($plain as $key => $types) {
  foreach (array_unique($types) as $type) {
    if (!in_array($type, $withPlugin[$key] ?? [], TRUE)) {
      $lost++;
      $fail++;
      printf("FAIL %s  plain Psalm reports %s but the plugin does not (a lost built-in sink)\n", $key, $type);
    }
  }
}

printf(
  "\n%d annotated lines checked, %d known false positive(s), %d known false negative(s); built-in parity: %d sink line(s) compared, %d lost.\n%s\n",
  $checked,
  $knownFalsePositives,
  $knownFalseNegatives,
  count($plain),
  $lost,
  $fail === 0 ? 'OK' : "$fail FAILURE(S)",
);
exit($fail === 0 ? 0 : 1);
