from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Category",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100, verbose_name="카테고리명")),
                ("slug", models.SlugField(max_length=120, unique=True, verbose_name="슬러그")),
            ],
            options={
                "verbose_name": "카테고리",
                "verbose_name_plural": "카테고리",
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="Product",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=200, verbose_name="상품명")),
                ("description", models.TextField(blank=True, verbose_name="설명")),
                ("price", models.DecimalField(decimal_places=0, max_digits=10, verbose_name="가격(포인트)")),
                (
                    "status",
                    models.CharField(
                        choices=[("ON_SALE", "판매 중"), ("RESERVED", "예약 중"), ("SOLD", "판매 완료")],
                        default="ON_SALE",
                        max_length=10,
                        verbose_name="거래 상태",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "category",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="products",
                        to="market.category",
                        verbose_name="카테고리",
                    ),
                ),
                (
                    "seller",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="products",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="판매자",
                    ),
                ),
            ],
            options={
                "verbose_name": "상품",
                "verbose_name_plural": "상품",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="ProductImage",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("image", models.ImageField(upload_to="products/", verbose_name="상품 이미지")),
                (
                    "product",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="images",
                        to="market.product",
                        verbose_name="상품",
                    ),
                ),
            ],
            options={
                "verbose_name": "상품 이미지",
                "verbose_name_plural": "상품 이미지",
            },
        ),
        migrations.CreateModel(
            name="Wishlist",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "product",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="wishlisted_by",
                        to="market.product",
                        verbose_name="상품",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="wishlists",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="사용자",
                    ),
                ),
            ],
            options={
                "verbose_name": "관심 상품",
                "verbose_name_plural": "관심 상품",
                "unique_together": {("user", "product")},
            },
        ),
    ]

