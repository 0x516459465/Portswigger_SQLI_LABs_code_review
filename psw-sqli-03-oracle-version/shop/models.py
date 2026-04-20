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
    """
    Shop catalog backed by Oracle.

    Oracle stores unquoted identifiers in uppercase, so raw SQL can
    still target this table as `products` (case-insensitive match).
    """

    name = OracleVarcharField(max_length=200)
    category = OracleVarcharField(max_length=100)
    description = OracleVarcharField(max_length=2000)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    released = models.BooleanField(default=True)

    class Meta:
        db_table = "products"

    def __str__(self) -> str:
        return f"{self.name} ({self.category})"


class Flag(models.Model):
    """
    Stores the CTF flag in a dedicated table.

    Normal browsing never reads from this table - only a UNION-based
    injection that discovers the schema (e.g. via ALL_TABLES) and
    projects `content` into one of the product columns can surface it.
    """

    content = OracleVarcharField(max_length=200)

    class Meta:
        db_table = "flags"

    def __str__(self) -> str:
        return self.content
