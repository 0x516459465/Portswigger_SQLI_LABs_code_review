from django.db import models


class OracleVarcharField(models.CharField):
    """CharField that emits VARCHAR2 (not NVARCHAR2) on Oracle.

    Django's Oracle backend defaults CharField to NVARCHAR2 (AL16UTF16).
    Oracle's catalog views (V$VERSION.BANNER, ALL_TABLES.TABLE_NAME, ...)
    are VARCHAR2 (AL32UTF8). UNION across the two raises
    ORA-12704: character set mismatch.
    """

    def db_type(self, connection):
        if connection.vendor == "oracle":
            return f"VARCHAR2({self.max_length})"
        return super().db_type(connection)


class Product(models.Model):
    name = OracleVarcharField(max_length=200)
    category = OracleVarcharField(max_length=100)
    description = OracleVarcharField(max_length=2000)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    released = models.BooleanField(default=True)

    class Meta:
        db_table = "products"

    def __str__(self) -> str:
        return f"{self.name} ({self.category})"


class User(models.Model):
    """
    Application user.

    Passwords are stored in plaintext because the lab's teaching goal
    is to recover admin credentials via UNION-based SQLi and then log
    in with them. Hashing would obscure that step.
    """

    username = OracleVarcharField(max_length=150, unique=True)
    password = OracleVarcharField(max_length=200)
    email = OracleVarcharField(max_length=254, blank=True, default="")
    is_admin = models.BooleanField(default=False)

    class Meta:
        db_table = "users"

    def __str__(self) -> str:
        return self.username


class Flag(models.Model):
    """
    Flag revealed on the my-account page only when the current session
    is bound to an administrator account. Stored in its own table so
    the attacker cannot trivially UNION it out via the storefront
    injection - they must enumerate USER_TABLES/USER_TAB_COLUMNS,
    recover credentials, and actually log in.
    """

    content = OracleVarcharField(max_length=200)

    class Meta:
        db_table = "flags"

    def __str__(self) -> str:
        return self.content
