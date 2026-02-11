from django import forms

from .models import Post, Question, Answer


class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ('title', 'content')


class QuestionForm(forms.ModelForm):
    class Meta:
        model = Question
        fields = ('title', 'content', 'bounty')


class AnswerForm(forms.ModelForm):
    class Meta:
        model = Answer
        fields = ('content',)

