from django.urls import path

from . import views

urlpatterns = [
    path('', views.product_list_view, name='market'),
    path('products/new/', views.product_create_view, name='product_create'),
    path('products/<int:pk>/', views.product_detail_view, name='product_detail'),
    path('products/<int:pk>/wishlist-toggle/', views.toggle_wishlist_view, name='wishlist_toggle'),
]

