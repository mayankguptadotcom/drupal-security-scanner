<?php

/**
 * @file
 * PHP built-in sinks. Plain Psalm reports every line below; the plugin must
 * keep reporting them. 1.0.0 redeclared some built-ins in its stubs and lost
 * every shell-execution sink — tests/check.php also compares this file with a
 * plain-Psalm run, so a lost built-in sink fails the build even if the
 * expectations here were edited.
 */

function builtin_exec() { exec($_GET['a']); } // expect: TaintedShell
function builtin_system() { system($_GET['a']); } // expect: TaintedShell
function builtin_shell_exec() { shell_exec($_GET['a']); } // expect: TaintedShell
function builtin_passthru() { passthru($_GET['a']); } // expect: TaintedShell
function builtin_popen() { popen($_GET['a'], 'r'); } // expect: TaintedShell
function builtin_proc_open() { proc_open($_GET['a'], [], $pipes); } // expect: TaintedShell
function builtin_unserialize() { unserialize($_GET['a']); } // expect: TaintedUnserialize
function builtin_include() { include $_GET['a']; } // expect: TaintedInclude
function builtin_eval() { eval($_GET['a']); } // expect: TaintedEval
function builtin_echo() { echo $_GET['a']; } // expect: TaintedHtml
function builtin_printf() { printf($_GET['a']); } // expect: TaintedHtml
function builtin_header() { header($_GET['a']); } // expect: TaintedHeader
function builtin_setcookie() { setcookie('x', $_GET['a']); } // expect: TaintedCookie
function builtin_file_put_contents() { file_put_contents($_GET['a'], 'x'); } // expect: TaintedFile
function builtin_file_get_contents() { return file_get_contents($_GET['a']); } // expect: TaintedFile
function builtin_readfile() { readfile($_GET['a']); } // expect: TaintedFile
function builtin_copy() { copy($_GET['a'], '/tmp/x'); } // expect: TaintedFile
function builtin_rename() { rename($_GET['a'], '/tmp/x'); } // expect: TaintedFile
function builtin_unlink() { unlink($_GET['a']); } // expect: TaintedFile
function builtin_extract() { extract($_GET); } // expect: TaintedExtract
function builtin_call_user_func() { call_user_func($_GET['a']); } // expect: TaintedCallable
