<?php

/**
 * Fixture for URL / dangerous-protocol XSS (bucket C — the biggest in-PHP win).
 *
 * A user-controlled string used as a URL/href is XSS if it can be a
 * `javascript:`/`data:` URI. The ONLY thing that neutralises that is protocol
 * stripping (UrlHelper::stripDangerousProtocols / filterBadProtocols) — NOT
 * Html::escape or Xss::filter (a javascript: URI has no HTML special chars and
 * survives them untouched).
 *
 * Expected: the _vuln cases flag, the _safe cases do not. We use this to see
 * what our current model gets right and what to fix.
 */

use Drupal\Core\Url;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Component\Utility\Xss;
use Drupal\Core\Render\RendererInterface;
use Symfony\Component\HttpFoundation\Request;

function url_vuln_fromuri(Request $request): Url
{
    $u = $request->query->get('u');
    return Url::fromUri($u);                         // VULN: tainted URI, no stripping
}

function url_vuln_xss_filter_is_not_enough(Request $request): Url
{
    $u = $request->query->get('u');
    return Url::fromUri(Xss::filter($u));            // VULN: html-escape does NOT clean a javascript: URI
}

function url_vuln_href_in_markup(Request $request, RendererInterface $r): void
{
    $u = $request->query->get('u');
    $build = ['#markup' => '<a href="' . Xss::filter($u) . '">x</a>'];  // VULN: same trap, in markup
    $r->render($build);
}

function url_safe_stripped(Request $request): Url
{
    $u = $request->query->get('u');
    return Url::fromUri(UrlHelper::stripDangerousProtocols($u));  // SAFE: protocol stripped
}

function url_safe_filter_bad(Request $request): Url
{
    $u = $request->query->get('u');
    return Url::fromUri(UrlHelper::filterBadProtocols($u));       // SAFE: protocol filtered
}
