from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .models import Category, Product, Wishlist


def product_list_view(request):
    """상품 목록 + 검색/카테고리/정렬."""
    qs = Product.objects.select_related('seller', 'category').prefetch_related('images')

    query = request.GET.get('q', '').strip()
    category_slug = request.GET.get('category')
    order = request.GET.get('order', 'latest')

    if query:
        qs = qs.filter(title__icontains=query)

    if category_slug:
        qs = qs.filter(category__slug=category_slug)

    if order == 'price_asc':
        qs = qs.order_by('price')
    elif order == 'price_desc':
        qs = qs.order_by('-price')
    else:  # latest
        qs = qs.order_by('-created_at')

    categories = Category.objects.all()

    context = {
        'products': qs,
        'categories': categories,
        'current_query': query,
        'current_category_slug': category_slug,
        'current_order': order,
    }
    return render(request, 'market.html', context)


def product_detail_view(request, pk):
    """상품 상세 페이지."""
    product = get_object_or_404(
        Product.objects.select_related('seller', 'category').prefetch_related('images'),
        pk=pk,
    )
    wished = False
    if request.user.is_authenticated:
        wished = Wishlist.objects.filter(user=request.user, product=product).exists()

    return render(
        request,
        'market_product_detail.html',
        {
            'product': product,
            'wished': wished,
        },
    )


@login_required
def product_create_view(request):
    """간단한 상품 등록 폼 (다중 이미지 업로드)."""
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        price = request.POST.get('price', '').strip()
        category_id = request.POST.get('category')
        images = request.FILES.getlist('images')

        if not title or not price:
            # 아주 간단한 검증만 수행 (추후 Form 클래스로 개선 가능)
            categories = Category.objects.all()
            return render(
                request,
                'market_product_form.html',
                {
                    'categories': categories,
                    'error': '상품명과 가격은 필수입니다.',
                },
            )

        category = None
        if category_id:
            category = get_object_or_404(Category, id=category_id)

        # [취약점] A06: Insecure Design
        # 가격 검증 없이 그대로 저장 (음수, 엄청 큰 수 등 허용)
        # price = request.POST.get('price', '').strip() 
        price = request.POST.get('price') # strip() 제거 등 최소한의 가공도 없이 저장

        product = Product.objects.create(
            seller=request.user,
            title=title,
            description=description,
            price=price,
            category=category,
        )

        from .models import ProductImage

        for image_file in images:
            ProductImage.objects.create(product=product, image=image_file)

        return redirect('product_detail', pk=product.pk)

    categories = Category.objects.all()
    return render(request, 'market_product_form.html', {'categories': categories})


@login_required
@require_POST
def toggle_wishlist_view(request, pk):
    """관심 상품(찜) 토글."""
    product = get_object_or_404(Product, pk=pk)
    wishlist, created = Wishlist.objects.get_or_create(user=request.user, product=product)
    if not created:
        wishlist.delete()
    return redirect('product_detail', pk=pk)

