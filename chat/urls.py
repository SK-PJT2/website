# chat/urls.py
from django.urls import path
from . import views

app_name = 'chat'

urlpatterns = [
    path('', views.chat_list, name='chat_list'), # localhost/chat/ 주소
    path('start/<int:product_id>/', views.get_or_create_room, name='get_or_create_room'),
    path('room/<int:room_id>/', views.room_detail, name='room_detail'),
]