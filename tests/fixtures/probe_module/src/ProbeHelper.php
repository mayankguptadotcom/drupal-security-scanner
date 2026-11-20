<?php

namespace Drupal\probe_module;

class ProbeHelper {
  // Reached through \Drupal::service('probe_module.helper') in ProbeController:
  // the issue is reported here, at the sink. queryRange() is used only here,
  // because Psalm drops a path through a helper into a sink another path in the
  // same analysis already reaches (see tests/fixtures/psalm_limits.php).
  public function raw(string $sql, \Drupal\Core\Database\Connection $db) { return $db->queryRange($sql, 0, 10); } // expect: TaintedSql
}
