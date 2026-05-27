from __future__ import annotations

import logging
from typing import Any, cast

from pulpcore.plugin.tasking import dispatch
from pulpcore.plugin.viewsets import (
    ContentGuardFilter,
    ContentGuardViewSet,
    OperationPostponedResponse,
)
from rest_framework import viewsets

from pulp_trustify.app.models import TrustifyGuard
from pulp_trustify.app.serializers import (
    ScanSerializer,
    TrustifyGuardSerializer,
)

logger = logging.getLogger(__name__)


class TrustifyGuardViewSet(ContentGuardViewSet):
    """REST API viewset for managing TrustifyGuard instances."""

    endpoint_name = "guard"
    queryset = TrustifyGuard.objects.all()
    serializer_class = TrustifyGuardSerializer
    filterset_class = ContentGuardFilter


class ScanViewSet(viewsets.ViewSet):
    """ViewSet for scanning repositories for vulnerabilities."""

    serializer_class = ScanSerializer

    def create(self, request):
        """Dispatch a scan task for the specified repository."""
        from django.conf import settings
        from rest_framework.exceptions import ValidationError

        if not getattr(settings, "TRUSTIFY_SCAN_ENABLED", True):
            logger.warning("Scan request rejected: scanning disabled")
            raise ValidationError("Scanning is disabled.")

        from pulp_trustify.app.tasks import scan_repository

        serializer = ScanSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        data = cast(dict[str, Any], serializer.validated_data)
        repository = data["repository"]

        result = dispatch(
            scan_repository,
            exclusive_resources=[repository],
            kwargs={"repository_pk": str(repository.pk)},
        )

        logger.info("Scan dispatched for repository '%s'", repository.pk)

        return OperationPostponedResponse(result, request)
