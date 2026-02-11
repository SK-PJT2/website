"""
ASGI config for config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os
import django
from django.core.asgi import get_asgi_application

# 1. 환경 변수 설정
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# 2. Django 초기화 및 HTTP ASGI 애플리케이션 생성 (순서 중요)
# get_asgi_application()은 내부적으로 django.setup()을 포함합니다.
django_asgi_app = get_asgi_application()

# 3. Channels 관련 라이브러리는 반드시 위 설정 이후에 import 해야 합니다.
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import chat.routing

application = ProtocolTypeRouter({
    # http 요청은 위에서 생성한 애플리케이션이 처리
    "http": django_asgi_app,
    
    # websocket 요청 처리
    "websocket": AuthMiddlewareStack(
        URLRouter(
            chat.routing.websocket_urlpatterns
        )
    ),
})