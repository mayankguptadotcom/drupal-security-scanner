<?php

/**
 * @file
 * The Drupal taint model: how request input is read, and the Drupal APIs it
 * must not reach unescaped. Every line is a real vulnerability.
 */

use Drupal\Core\Database\Connection;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\Markup;
use Drupal\Core\Render\RendererInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

// Request input, read every common way, printed raw.
function src_get(Request $r) { print $r->get('x'); } // expect: TaintedHtml
function src_query(Request $r) { print $r->query->get('x'); } // expect: TaintedHtml
function src_post(Request $r) { print $r->request->get('x'); } // expect: TaintedHtml
function src_body(Request $r) { print $r->getContent(); } // expect: TaintedHtml
function src_stack(RequestStack $s) { print $s->getCurrentRequest()->query->get('x'); } // expect: TaintedHtml
function src_static() { print \Drupal::request()->query->get('x'); } // expect: TaintedHtml
function src_cookie(Request $r) { print $r->cookies->get('x'); } // expect: TaintedHtml
function src_header(Request $r) { print $r->headers->get('x'); } // expect: TaintedHtml
function src_path(Request $r) { print $r->getPathInfo(); } // expect: TaintedHtml
function src_form(FormStateInterface $f) { print $f->getValue('x'); } // expect: TaintedHtml
function src_route(RouteMatchInterface $m) { print $m->getRawParameter('x'); } // expect: TaintedHtml

// Drupal sinks.
function sink_sql(Request $r, Connection $db) { return $db->query('SELECT * FROM {node} WHERE title = ' . $r->query->get('t')); } // expect: TaintedSql
function sink_markup_create(Request $r) { return Markup::create($r->query->get('h')); } // expect: TaintedHtml
function sink_markup_key(Request $r, RendererInterface $renderer) { $b = ['#markup' => $r->query->get('h')]; return $renderer->render($b); } // expect: TaintedHtml
function sink_translation_string(Request $r) { return new TranslatableMarkup($r->query->get('s')); } // expect: TaintedHtml
function sink_redirect(Request $r) { return new RedirectResponse($r->query->get('u')); } // expect: TaintedHeader
function sink_where(Request $r, Connection $db) { return $db->select('node', 'n')->where('title = ' . $r->query->get('t'))->execute(); } // expect: TaintedSql
