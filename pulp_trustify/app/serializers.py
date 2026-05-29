from __future__ import annotations

from pulpcore.plugin.models import Repository
from pulpcore.plugin.serializers import ContentGuardSerializer
from rest_framework import serializers

from pulp_trustify.app.models import ScanAdvisory, TrustifyGuard


class TrustifyGuardSerializer(ContentGuardSerializer):
    """Serializer for the TrustifyGuard model."""

    class Meta(ContentGuardSerializer.Meta):
        model = TrustifyGuard


class ScanSerializer(serializers.Serializer):
    """Serializer for scan endpoint."""

    repository = serializers.CharField(
        help_text="Repository href to scan.",
        required=True,
    )

    def validate_repository(self, value):
        pk = value.rstrip("/").split("/")[-1]
        try:
            return Repository.objects.get(pk=pk)
        except Repository.DoesNotExist:
            raise serializers.ValidationError(f"Repository not found: {value}")


class ScanAdvisorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanAdvisory
        fields = [
            "repository",
            "content_pk",
            "purl",
            "cve_ids",
            "details",
            "severity",
            "detection_mode",
            "action",
            "scanned_at",
        ]
        read_only_fields = fields
