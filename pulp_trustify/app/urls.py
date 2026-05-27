"""URL configuration for pulp_trustify plugin."""

from django.urls import path

from pulp_trustify.app.viewsets import ScanViewSet

urlpatterns = [
    path(
        "pulp/api/v3/trustify/scan/",
        ScanViewSet.as_view({"post": "create"}),
        name="scan",
    ),
]
