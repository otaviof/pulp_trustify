from __future__ import annotations

from pulpcore.plugin.serializers import ContentGuardSerializer

from pulp_trustify.app.models import TrustifyGuard


class TrustifyGuardSerializer(ContentGuardSerializer):
    """Serializer for the TrustifyGuard model."""

    class Meta:
        model = TrustifyGuard
        fields = ContentGuardSerializer.Meta.fields
