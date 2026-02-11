from django.db import models
from django.conf import settings
from market.models import Product

class ChatRoom(models.Model):
    # 어떤 상품에 대한 채팅인지 연결
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='chat_rooms')
    # 구매자와 판매자 연결
    buyer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='buyer_rooms')
    seller = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='seller_rooms')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # 한 상품에 대해 구매자와 판매자 간의 방은 하나만 존재하도록 제한
        unique_together = ('product', 'buyer', 'seller')

    def __str__(self):
        return f"[{self.product.title}] {self.buyer.username} & {self.seller.username}"

class Message(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp'] # 메시지는 시간순으로 정렬