"""URL configuration for pulp_trustify plugin."""

from django.conf import settings
from django.urls import path

from pulp_trustify.app.viewsets import (
    GateAdvisoryViewSet,
    NpmBulkAdvisoryView,
    ScanAdvisoryViewSet,
    ScanViewSet,
)

if settings.DOMAIN_ENABLED:
    API_ROOT = "/<slug:pulp_domain>/api/v3/"
else:
    API_ROOT = "/api/v3/"
API_ROOT = settings.API_ROOT.strip("/") + API_ROOT

urlpatterns = [
    path(
        API_ROOT + "trustify/scan/",
        ScanViewSet.as_view({"post": "create"}),
        name="scan",
    ),
    path(
        API_ROOT + "trustify/advisories/",
        ScanAdvisoryViewSet.as_view({"get": "list"}),
        name="advisories",
    ),
    path(
        API_ROOT + "trustify/gate-advisories/",
        GateAdvisoryViewSet.as_view({"get": "list"}),
        name="gate-advisories",
    ),
    path(
        API_ROOT + "trustify/-/npm/v1/security/advisories/bulk",
        NpmBulkAdvisoryView.as_view(),
        name="npm-audit-bulk",
    ),
]
