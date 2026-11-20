<?php

/**
 * Fixture for RenderArrayTainter.
 *
 * Tainted request input is placed into render-array keys two ways — as an array
 * LITERAL and by ASSIGNMENT — to document how the hook behaves for each.
 *
 *   #markup  = raw-HTML sink     -> expect a TaintedHtml report (both styles)
 *   #title   = auto-escaped key  -> expect NO report
 *
 * Known gap: RenderArrayTainter fires on ArrayItem nodes, which exist only in
 * array literals. Safe keys built by assignment are therefore NOT de-tainted
 * yet (a false positive). Assignment style is very common in real Drupal code.
 */

use Drupal\Core\Render\RendererInterface;
use Symfony\Component\HttpFoundation\Request;

function render_literal(Request $request, RendererInterface $renderer): void
{
    $evil = $request->query->get('x');

    $dangerous = ['#markup' => $evil];
    $renderer->render($dangerous); // expect: TaintedHtml

    $safe = ['#title' => $evil];
    $renderer->render($safe); // expect: none
}

function render_assignment(Request $request, RendererInterface $renderer): void
{
    $evil = $request->query->get('x');

    $dangerous = [];
    $dangerous['#markup'] = $evil;
    $renderer->render($dangerous); // expect: TaintedHtml

    $safe = [];
    // RenderArrayTainter handles ['#title' => $x] but not $a['#title'] = $x.
    $safe['#title'] = $evil;
    $renderer->render($safe); // known-false-positive: TaintedHtml
}
