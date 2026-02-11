from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models


class Post(models.Model):
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='posts',
        verbose_name='작성자',
    )
    title = models.CharField(max_length=200, verbose_name='제목')
    content = models.TextField(verbose_name='내용', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '게시글'
        verbose_name_plural = '게시글'
        ordering = ['-created_at']

    def __str__(self) -> str:
        return self.title


class PostAttachment(models.Model):
    post = models.ForeignKey(
        Post,
        on_delete=models.CASCADE,
        related_name='attachments',
        verbose_name='게시글',
    )
    file = models.FileField(upload_to='board_attachments/', verbose_name='첨부파일')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = '게시글 첨부'
        verbose_name_plural = '게시글 첨부'

    def __str__(self) -> str:
        return f'{self.post_id} attachment'


class Question(models.Model):
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='questions',
        verbose_name='질문자',
    )
    title = models.CharField(max_length=200, verbose_name='제목')
    content = models.TextField(verbose_name='내용', blank=True)
    bounty = models.DecimalField(
        max_digits=10,
        decimal_places=0,
        default=0,
        verbose_name='현상금(포인트)',
        help_text='포인트 금융 시스템(3번) 구현 전까지는 지급 로직이 동작하지 않습니다.',
    )
    is_solved = models.BooleanField(default=False, verbose_name='해결 여부')
    accepted_answer = models.ForeignKey(
        'Answer',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='+',
        verbose_name='채택된 답변',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '질문'
        verbose_name_plural = '질문'
        ordering = ['-created_at']

    def __str__(self) -> str:
        return self.title


class Answer(models.Model):
    question = models.ForeignKey(
        Question,
        on_delete=models.CASCADE,
        related_name='answers',
        verbose_name='질문',
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='answers',
        verbose_name='답변자',
    )
    content = models.TextField(verbose_name='답변')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = '답변'
        verbose_name_plural = '답변'
        ordering = ['created_at']

    def __str__(self) -> str:
        return f'Answer #{self.id}'


class Comment(models.Model):
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='comments',
        verbose_name='작성자',
    )
    content = models.TextField(verbose_name='댓글')
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='replies',
        verbose_name='부모 댓글',
    )

    # 대상(게시글/질문/답변)에 공통으로 붙이는 Generic FK
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    target = GenericForeignKey('content_type', 'object_id')

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = '댓글'
        verbose_name_plural = '댓글'
        ordering = ['created_at']

    def __str__(self) -> str:
        return f'Comment #{self.id}'

