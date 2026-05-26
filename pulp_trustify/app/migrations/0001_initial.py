from __future__ import annotations

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("core", "__first__")]

    operations = [
        migrations.CreateModel(
            name="TrustifyGuard",
            fields=[
                (
                    "contentguard_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="core.contentguard",
                    ),
                ),
            ],
            options={
                "default_related_name": "%(app_label)s_%(model_name)s",
            },
            bases=("core.contentguard",),
        ),
    ]
