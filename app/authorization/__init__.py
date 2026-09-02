"""Authorization module — the cross-cutting server-side policy layer.

Renders a single ALLOW/DENY decision per sensitive request, default-deny. It is
a distinct logical layer, not a module owning tables. See design
"Authorization layer": AuthorizationService.
"""
