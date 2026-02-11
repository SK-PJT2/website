from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path('signup/', views.SignUpView.as_view(), name='signup'),
    # path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    # [취약점] 커스텀 취약한 로그인 뷰 연결
    path('login/', views.login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('profile/<str:nickname>/', views.profile_view, name='profile'),
    path('security/secondary-password/', views.secondary_password_set_view, name='secondary_password_set'),
]
