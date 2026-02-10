from django import forms
from django.contrib.auth.forms import UserCreationForm

from .models import CustomUser


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = UserCreationForm.Meta.fields + ('nickname', 'email', 'profile_image')


class SecondaryPasswordSetForm(forms.Form):
    """2차 비밀번호를 새로 설정하거나 변경하는 폼."""

    new_secondary_password = forms.CharField(
        label='새 2차 비밀번호',
        widget=forms.PasswordInput,
        help_text='포인트 관련 액션을 보호하기 위한 추가 비밀번호입니다.',
    )
    new_secondary_password_confirm = forms.CharField(
        label='새 2차 비밀번호 확인',
        widget=forms.PasswordInput,
    )

    def clean(self):
        cleaned_data = super().clean()
        pw1 = cleaned_data.get('new_secondary_password')
        pw2 = cleaned_data.get('new_secondary_password_confirm')
        if pw1 and pw2 and pw1 != pw2:
            raise forms.ValidationError('2차 비밀번호가 서로 일치하지 않습니다.')
        return cleaned_data


class SecondaryPasswordVerifyForm(forms.Form):
    """민감 액션 직전에 2차 비밀번호를 확인할 때 사용하는 폼."""

    secondary_password = forms.CharField(
        label='2차 비밀번호',
        widget=forms.PasswordInput,
    )
