<?php

namespace Drupal\probe_module\Controller;

use Drupal\node\NodeInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Route parameters reach controller arguments straight from the URL.
 */
class ProbeController {

  public function hello(string $name, int $count) {
    print $name; // expect: TaintedHtml
    print $count; // expect: none
    return ['#markup' => 'ok'];
  }

  public function node(NodeInterface $node) {
    // An upcast entity is loaded by Drupal, not attacker text.
    return ['#theme' => 'x', '#node' => $node]; // expect: none
  }

  public function notARoute(string $name) {
    print $name; // expect: none
  }

  public function services(Request $r) {
    \Drupal::service('twig')->createTemplate($r->query->get('t')); // expect: TaintedHtml
    \Drupal::service('file_system')->deleteRecursive('public://' . $r->query->get('p')); // expect: TaintedFile
    \Drupal::service('probe_module.helper')->raw('SELECT ' . $r->query->get('c'), \Drupal::database()); // expect: none
    \Drupal::getContainer()->get('file_system')->delete($r->query->get('p')); // expect: TaintedFile
  }

  public function fileSystem(Request $r, \Drupal\Core\File\FileSystemInterface $fs) {
    $fs->saveData('x', 'public://' . $r->query->get('p')); // expect: TaintedFile
    $fs->copy($r->query->get('a'), 'public://b'); // expect: TaintedFile
    $fs->saveData($r->query->get('data'), 'public://fixed.txt'); // expect: none
  }

}
