from django.contrib import admin

from .models import Answer, Comment, Post, PostAttachment, Question


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'author', 'created_at')
    search_fields = ('title', 'content', 'author__username', 'author__nickname')


@admin.register(PostAttachment)
class PostAttachmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'post', 'file', 'uploaded_at')


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'author', 'bounty', 'is_solved', 'created_at')
    list_filter = ('is_solved',)
    search_fields = ('title', 'content', 'author__username', 'author__nickname')


@admin.register(Answer)
class AnswerAdmin(admin.ModelAdmin):
    list_display = ('id', 'question', 'author', 'created_at')
    search_fields = ('content', 'author__username', 'author__nickname')


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'content_type', 'object_id', 'parent', 'created_at')
    search_fields = ('content', 'author__username', 'author__nickname')

