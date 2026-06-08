"""URL configuration for pulp_trustify plugin."""

from django.urls import path

from pulp_trustify.app.viewsets import (
    NpmBulkAdvisoryView,
    ScanAdvisoryViewSet,
    ScanViewSet,
)

urlpatterns = [
    path(
        "pulp/api/v3/trustify/scan/",
        ScanViewSet.as_view({"post": "create"}),
        name="scan",
    ),
    path(
        "pulp/api/v3/trustify/advisories/",
        ScanAdvisoryViewSet.as_view({"get": "list"}),
        name="advisories",
    ),
    path(
        "pulp/api/v3/trustify/-/npm/v1/security/advisories/bulk",
        NpmBulkAdvisoryView.as_view(),
        name="npm-audit-bulk",
    ),
]
