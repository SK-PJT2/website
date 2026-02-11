# chat/views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from market.models import Product
from .models import ChatRoom
from django.db.models import Q
@login_required
def get_or_create_room(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    
    # 본인이 올린 상품이면 채팅 불가 (선택 사항)
    if product.seller == request.user:
        return redirect('market_product_detail', pk=product_id)

    # 방 조회 또는 생성
    room, created = ChatRoom.objects.get_or_create(
        product=product,
        buyer=request.user,
        seller=product.seller
    )
    
    return redirect('chat:room_detail', room_id=room.id)

@login_required
def room_detail(request, room_id):
    room = get_object_or_404(ChatRoom, id=room_id)
    
    # [취약점] A01: Broken Access Control (IDOR)
    # 소유자 검증 로직 제거! 누구든지 room_id만 알면 접근 가능
    # if request.user != room.buyer and request.user != room.seller:
    #     return redirect('home')
        
    messages = room.messages.all() # 이전 대화 내역 불러오기
    return render(request, 'chat/room.html', {
        'room': room,
        'chat_messages': messages
    })

@login_required
def chat_list(request):
    # 내가 구매자이거나 판매자인 모든 채팅방을 최신 메시지순으로 가져옵니다.
    rooms = ChatRoom.objects.filter(
        Q(buyer=request.user) | Q(seller=request.user)
    ).order_by('-created_at')
    
    return render(request, 'chat/chat_list.html', {'rooms': rooms})