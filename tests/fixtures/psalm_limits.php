<?php

/**
 * @file
 * Limits of Psalm's taint analysis itself, pinned so a fix is noticed.
 *
 * Psalm de-duplicates by sink: once a path reaches Connection::query(), a
 * second path that reaches the same sink through a helper function is not
 * reported. Direct call sites are each reported.
 */

use Drupal\Core\Database\Connection;
use Symfony\Component\HttpFoundation\Request;

function limit_direct(Request $r, Connection $db) { return $db->query('SELECT 1 WHERE a = ' . $r->query->get('a')); } // expect: TaintedSql
function limit_via_helper(Request $r, Connection $db) { return limit_helper('SELECT 2 WHERE b = ' . $r->query->get('b'), $db); }
function limit_helper(string $sql, Connection $db) { return $db->query($sql); } // known-false-negative: TaintedSql
