from __future__ import annotations

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("trustify", "0001_initial"),
        ("core", "__first__"),
    ]

    operations = [
        migrations.CreateModel(
            name="ScanAdvisory",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("content_pk", models.UUIDField()),
                ("purl", models.CharField(max_length=512)),
                ("cve_ids", models.JSONField(default=list)),
                ("severity", models.CharField(max_length=16)),
                ("detection_mode", models.CharField(max_length=16)),
                ("action", models.CharField(max_length=64)),
                (
                    "scanned_at",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "repository",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scan_advisories",
                        to="core.repository",
                    ),
                ),
            ],
        ),
        migrations.AddIndex(
            model_name="scanadvisory",
            index=models.Index(
                fields=["repository", "scanned_at"],
                name="pulp_trustify_scanadvisory_repo_scanned_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="scanadvisory",
            index=models.Index(
                fields=["purl"],
                name="pulp_trustify_scanadvisory_purl_idx",
            ),
        ),
    ]
