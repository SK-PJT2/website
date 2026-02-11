from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import CreateView

from .forms import (
    CustomUserCreationForm,
    SecondaryPasswordSetForm,
)


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
            user.set_secondary_password(new_pw)
            user.save(update_fields=['secondary_password'])
            # 설정 후에는 자신의 프로필 페이지로 이동
            if user.nickname:
                return redirect('profile', nickname=user.nickname)
            return redirect('home')
    else:
        form = SecondaryPasswordSetForm()

    return render(request, 'accounts/secondary_password_set.html', {'form': form})
