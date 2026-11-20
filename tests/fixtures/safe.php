<?php

/**
 * @file
 * Safe code. Reporting any line here is a false positive; each was checked
 * against Drupal core (Drupal 11), and the reason is next to it.
 */

use Drupal\Core\Database\Connection;
use Drupal\Core\Link;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Render\RendererInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Url;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

// Messages are printed with {{ message }}, which Twig autoescapes.
function safe_message(Request $r, MessengerInterface $m) { $m->addMessage($r->query->get('n')); } // expect: none
// Select::orderBy() runs the field through escapeField() when compiled.
function safe_order_by(Request $r, Connection $db) { return $db->select('node', 'n')->orderBy($r->query->get('sort'))->execute(); } // expect: none
// An integer cast removes the injection.
function safe_int_cast(Request $r, Connection $db) { return $db->query('SELECT * FROM {node} WHERE nid = ' . (int) $r->query->get('id')); } // expect: none
// '@' placeholders are escaped by the translation system.
function safe_placeholder(Request $r, RendererInterface $renderer) { $b = ['#markup' => new TranslatableMarkup('Hi @n', ['@n' => $r->query->get('n')])]; return $renderer->render($b); } // expect: none
// Presentation keys are autoescaped by Twig.
function safe_title_key(Request $r, RendererInterface $renderer) { $b = ['#title' => $r->query->get('t')]; return $renderer->render($b); } // expect: none
// Escaped output.
function safe_escaped(Request $r) { print htmlspecialchars($r->query->get('x')); } // expect: none
// A system-generated id is not attacker-controlled.
function safe_entity_id(\Drupal\Core\Entity\EntityInterface $e) { print $e->id(); } // expect: none
// Url::fromUri() rejects javascript:, data:, vbscript: and encoded variants
// (UnroutedUrlAssembler throws), so a user URI becomes at most an ordinary link.
function safe_url_from_uri(Request $r) { return Url::fromUri($r->query->get('u')); } // expect: none
function safe_link(Request $r) { return Link::fromTextAndUrl('x', Url::fromUri($r->query->get('u'))); } // expect: none
// JsonResponse encodes with JSON_HEX_TAG / JSON_HEX_QUOT / JSON_HEX_AMP.
function safe_json(Request $r) { return new JsonResponse(['q' => $r->query->get('q')]); } // expect: none
