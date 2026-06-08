from __future__ import annotations

from django.db import migrations, models

APP_LABEL = "trustify"
PREVIOUS = "0003_scanadvisory_details"


class Migration(migrations.Migration):
    dependencies = [
        (APP_LABEL, PREVIOUS),
    ]

    operations = [
        migrations.CreateModel(
            name="GateAdvisory",
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
                ("purl", models.CharField(max_length=512)),
                ("cve_ids", models.JSONField(default=list)),
                ("details", models.JSONField(default=list)),
                ("severity", models.CharField(max_length=16)),
                ("detection_mode", models.CharField(max_length=16)),
                ("action", models.CharField(max_length=16)),
                ("checked_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AddIndex(
            model_name="gateadvisory",
            index=models.Index(fields=["purl"], name="trustify_ga_purl_idx"),
        ),
        migrations.AddIndex(
            model_name="gateadvisory",
            index=models.Index(
                fields=["checked_at"], name="trustify_ga_checked_at_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="gateadvisory",
            index=models.Index(
                fields=["action"], name="trustify_ga_action_idx"
            ),
        ),
    ]
