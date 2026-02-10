from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    nickname = models.CharField(max_length=100, unique=True, blank=True, null=True, verbose_name='닉네임')
    points = models.DecimalField(default=0, max_digits=10, decimal_places=0, verbose_name='포인트')

    def __str__(self):
        return self.username
