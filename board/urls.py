from django.urls import path

from . import views

urlpatterns = [
    path('', views.board_home_view, name='board_home'),
    # posts
    path('posts/', views.post_list_view, name='post_list'),
    path('posts/new/', views.post_create_view, name='post_create'),
    path('posts/<int:pk>/', views.post_detail_view, name='post_detail'),
    # qna
    path('qna/', views.question_list_view, name='question_list'),
    path('qna/new/', views.question_create_view, name='question_create'),
    path('qna/<int:pk>/', views.question_detail_view, name='question_detail'),
    path('qna/<int:pk>/answers/new/', views.answer_create_view, name='answer_create'),
    path('qna/<int:question_pk>/answers/<int:answer_pk>/accept/', views.accept_answer_view, name='accept_answer'),
    # comments
    path('comments/new/', views.comment_create_view, name='comment_create'),
]

