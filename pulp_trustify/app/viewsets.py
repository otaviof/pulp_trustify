from __future__ import annotations

from pulpcore.plugin.viewsets import (
    ContentGuardFilter,
    ContentGuardViewSet,
)

from pulp_trustify.app.models import TrustifyGuard
from pulp_trustify.app.serializers import TrustifyGuardSerializer


class TrustifyGuardViewSet(ContentGuardViewSet):
    """REST API viewset for managing TrustifyGuard instances."""

    endpoint_name = "guard"
    queryset = TrustifyGuard.objects.all()
    serializer_class = TrustifyGuardSerializer
    filterset_class = ContentGuardFilter
