import logging
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import CreateView

from .forms import (
    CustomUserCreationForm,
    SecondaryPasswordSetForm,
)

logger = logging.getLogger(__name__)

# [취약점] A07: Authentication Failures & A09: Security Logging Failures
def login_view(request):
    """
    취약한 로그인 뷰:
    1. A09: 사용자의 비밀번호를 로그에 남김 (치명적!)
    2. A07: 아이디/비밀번호 에러를 상세히 구분하여 알려줌 (User Enumeration)
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # [A09] 로그에 비밀번호 노출
        logger.info(f"Login attempt - User: {username}, Password: {password}")

        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            # [A07] 사용자 존재 여부 확인 가능 (User Enumeration)
            User = get_user_model()
            if not User.objects.filter(username=username).exists():
                error_msg = "존재하지 않는 아이디입니다."
            else:
                error_msg = "비밀번호가 틀렸습니다."
            
            return render(request, 'registration/login.html', {'error': error_msg})

    return render(request, 'registration/login.html')


class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    success_url = reverse_lazy('login')
    template_name = 'registration/signup.html'


def profile_view(request, nickname):
    """닉네임 기반 프로필 페이지."""
    User = get_user_model()
    profile_user = get_object_or_404(User, nickname=nickname)
    return render(request, 'accounts/profile.html', {'profile_user': profile_user})


@login_required
def secondary_password_set_view(request):
    """
    로그인한 사용자가 2차 비밀번호를 설정/변경하는 페이지.
    금융 기능은 아직 구현하지 않았지만, 포인트 관련 보안을 위한 기반으로 사용됩니다.
    """
    user = request.user

    if request.method == 'POST':
        form = SecondaryPasswordSetForm(request.POST)
        if form.is_valid():
            new_pw = form.cleaned_data['new_secondary_password']
            
            # [취약점] A04: Cryptographic Failures
            # 해싱(make_password) 없이 평문 저장
            # user.set_secondary_password(new_pw) -> 안전한 방법
            user.secondary_password = new_pw  # 취약한 방법 (평문 저장)
            
            user.save(update_fields=['secondary_password'])
            # 설정 후에는 자신의 프로필 페이지로 이동
            if user.nickname:
                return redirect('profile', nickname=user.nickname)
            return redirect('home')
    else:
        form = SecondaryPasswordSetForm()

    return render(request, 'accounts/secondary_password_set.html', {'form': form})
