from django.contrib import admin

from .models import Category, Product, ProductImage, Wishlist


class ProductImageInline(admin.TabularInline):
    model = ProductImage
    extra = 1


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('title', 'seller', 'price', 'status', 'created_at')
    list_filter = ('status', 'category')
    search_fields = ('title', 'description', 'seller__username', 'seller__nickname')
    inlines = [ProductImageInline]


@admin.register(Wishlist)
class WishlistAdmin(admin.ModelAdmin):
    list_display = ('user', 'product', 'created_at')
    list_filter = ('created_at',)

