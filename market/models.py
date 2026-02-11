from django.conf import settings
from django.db import models


class Category(models.Model):
    name = models.CharField(max_length=100, verbose_name='카테고리명')
    slug = models.SlugField(max_length=120, unique=True, verbose_name='슬러그')

    class Meta:
        verbose_name = '카테고리'
        verbose_name_plural = '카테고리'
        ordering = ['name']

    def __str__(self) -> str:
        return self.name


class Product(models.Model):
    STATUS_CHOICES = [
        ('ON_SALE', '판매 중'),
        ('RESERVED', '예약 중'),
        ('SOLD', '판매 완료'),
    ]

    seller = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='products',
        verbose_name='판매자',
    )
    title = models.CharField(max_length=200, verbose_name='상품명')
    description = models.TextField(verbose_name='설명', blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=0, verbose_name='가격(포인트)')
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='products',
        verbose_name='카테고리',
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='ON_SALE',
        verbose_name='거래 상태',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '상품'
        verbose_name_plural = '상품'
        ordering = ['-created_at']

    def __str__(self) -> str:
        return self.title


class ProductImage(models.Model):
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='images',
        verbose_name='상품',
    )
    image = models.ImageField(upload_to='products/', verbose_name='상품 이미지')

    class Meta:
        verbose_name = '상품 이미지'
        verbose_name_plural = '상품 이미지'

    def __str__(self) -> str:
        return f'{self.product.title} 이미지'


class Wishlist(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='wishlists',
        verbose_name='사용자',
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='wishlisted_by',
        verbose_name='상품',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = '관심 상품'
        verbose_name_plural = '관심 상품'
        unique_together = ('user', 'product')

    def __str__(self) -> str:
        return f'{self.user} - {self.product}'

