from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("trustify", "0002_scanadvisory"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanadvisory",
            name="details",
            field=models.JSONField(default=list),
        ),
    ]
