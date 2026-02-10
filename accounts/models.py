from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password, check_password
from django.db import models


class CustomUser(AbstractUser):
    nickname = models.CharField(max_length=100, unique=True, blank=True, null=True, verbose_name='닉네임')
    points = models.DecimalField(default=0, max_digits=10, decimal_places=0, verbose_name='포인트')
    # 포인트 관련 민감 액션 보호용 2차 비밀번호 (해시 저장)
    secondary_password = models.CharField(
        max_length=128,
        blank=True,
        null=True,
        verbose_name='2차 비밀번호 해시',
        help_text='포인트 관련 보안을 위한 추가 비밀번호입니다.',
    )
    # 프로필 이미지
    profile_image = models.ImageField(
        upload_to='profiles/',
        blank=True,
        null=True,
        verbose_name='프로필 이미지',
    )

    def __str__(self):
        return self.username

    # 2차 비밀번호 설정/검증 유틸리티
    def set_secondary_password(self, raw_password: str) -> None:
        """원본 2차 비밀번호를 받아 해시로 저장합니다."""
        if raw_password:
            self.secondary_password = make_password(raw_password)
        else:
            self.secondary_password = None

    def check_secondary_password(self, raw_password: str) -> bool:
        """입력값이 저장된 2차 비밀번호와 일치하는지 검증합니다."""
        if not self.secondary_password or not raw_password:
            return False
        return check_password(raw_password, self.secondary_password)
