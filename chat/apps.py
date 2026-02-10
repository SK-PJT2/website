# chat/apps.py
from django.apps import AppConfig

class ChatConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'chat'  # <--- 이 'chat'이라는 이름이 INSTALLED_APPS의 설정과 일치해야 합니다.