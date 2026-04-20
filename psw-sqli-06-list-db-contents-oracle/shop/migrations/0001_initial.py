from django.db import migrations, models

from shop.models import OracleVarcharField


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Product",
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
                ("name", OracleVarcharField(max_length=200)),
                ("category", OracleVarcharField(max_length=100)),
                ("description", OracleVarcharField(max_length=2000)),
                ("price", models.DecimalField(decimal_places=2, max_digits=10)),
                ("released", models.BooleanField(default=True)),
            ],
            options={"db_table": "products"},
        ),
        migrations.CreateModel(
            name="User",
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
                ("username", OracleVarcharField(max_length=150, unique=True)),
                ("password", OracleVarcharField(max_length=200)),
                ("email", OracleVarcharField(max_length=254, blank=True, default="")),
                ("is_admin", models.BooleanField(default=False)),
            ],
            options={"db_table": "users"},
        ),
        migrations.CreateModel(
            name="Flag",
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
                ("content", OracleVarcharField(max_length=200)),
            ],
            options={"db_table": "flags"},
        ),
    ]
