from __future__ import annotations

import gzip
import logging
from typing import Any, cast

from pulpcore.plugin.tasking import dispatch
from pulpcore.plugin.viewsets import (
    ContentGuardFilter,
    ContentGuardViewSet,
    OperationPostponedResponse,
)
from rest_framework import parsers, viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from pulp_trustify.app.models import (
    GateAdvisory,
    ScanAdvisory,
    TrustifyGuard,
)
from pulp_trustify.app.serializers import (
    GateAdvisorySerializer,
    ScanAdvisorySerializer,
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


class ScanAdvisoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanAdvisory.objects.all()
    serializer_class = ScanAdvisorySerializer
    permission_classes = [IsAuthenticated]


class GateAdvisoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = GateAdvisory.objects.all()
    serializer_class = GateAdvisorySerializer
    permission_classes = [IsAuthenticated]


class GzipJSONParser(parsers.JSONParser):
    """Parser for gzip-compressed JSON request bodies."""

    def parse(self, stream, media_type=None, parser_context=None):
        from io import BytesIO

        from rest_framework.exceptions import ParseError

        request = parser_context.get("request") if parser_context else None
        encoding = request.META.get("HTTP_CONTENT_ENCODING") if request else None

        if encoding == "gzip":
            compressed = stream.read()
            if len(compressed) > 10 * 1024 * 1024:
                raise ParseError("Compressed payload exceeds 10MB limit")

            try:
                decompressed = gzip.decompress(compressed)
            except (gzip.BadGzipFile, OSError) as exc:
                raise ParseError("Invalid gzip data") from exc

            if len(decompressed) > 10 * 1024 * 1024:
                raise ParseError("Decompressed payload exceeds 10MB limit")

            stream = BytesIO(decompressed)

        return super().parse(stream, media_type, parser_context)


class NpmBulkAdvisoryView(APIView):
    """NPM bulk advisory endpoint for npm audit."""

    permission_classes = [AllowAny]
    parser_classes = [GzipJSONParser]

    def post(self, request):
        """Audit NPM packages for vulnerabilities."""
        from django.conf import settings
        from rest_framework.exceptions import ValidationError

        from pulp_trustify.app.models import _get_client
        from pulp_trustify.audit import audit_packages
        from pulp_trustify.client.client import TrustifyError

        if not getattr(settings, "TRUSTIFY_NPM_AUDIT_ENABLED", True):
            logger.debug("NPM audit disabled via settings")
            return Response({})

        if not settings.TRUSTIFY_URL:
            logger.debug("NPM audit disabled (no TRUSTIFY_URL)")
            return Response({})

        packages = request.data
        if not isinstance(packages, dict):
            raise ValidationError("Request body must be dict[str, list[str]]")

        for name, versions in packages.items():
            if not isinstance(versions, list) or not all(
                isinstance(v, str) for v in versions
            ):
                raise ValidationError(
                    f"'{name}' versions must be a list of strings"
                )

        try:
            result = audit_packages(
                client=_get_client(),
                packages=packages,
                threshold=settings.TRUSTIFY_SEVERITY_THRESHOLD,
                fail_open=settings.TRUSTIFY_FAIL_OPEN,
                batch_size=settings.TRUSTIFY_BATCH_SIZE,
                base_url=(
                    settings.TRUSTIFY_URL
                    if settings.TRUSTIFY_ENRICH_DETAILS
                    else ""
                ),
            )
            return Response(result)
        except TrustifyError as exc:
            if settings.TRUSTIFY_FAIL_OPEN:
                logger.warning(
                    "NPM audit failed (fail_open=True): %s",
                    exc,
                )
                return Response({})
            logger.error("NPM audit failed (fail_open=False): %s", exc)
            return Response(
                {"error": "Vulnerability service unavailable"},
                status=503,
            )
