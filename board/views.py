from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.conf import settings
from django.db import connection, DatabaseError
from django.http import HttpResponse # A10용
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .forms import AnswerForm, PostForm, QuestionForm
from .models import Answer, Comment, Post, Question


def board_home_view(request):
    return render(request, 'board/home.html')


# -------- 게시판(정보공유) --------
def post_list_view(request):
    search_query = request.GET.get('q', '')
    
    if search_query:
        # [취약점] A05: SQL Injection
        # 사용자 입력을 SQL 쿼리에 직접 포맷팅 (절대 금지!)
        # 입력값 예시: ' OR '1'='1 (모든 글 노출)
        sql = f"SELECT * FROM board_post WHERE title LIKE '%%{search_query}%%'"
        
        # Raw Query 실행
        posts = Post.objects.raw(sql)
    else:
        posts = Post.objects.select_related('author')

    return render(request, 'board/post_list.html', {'posts': posts})


def post_detail_view(request, pk):
    try:
        post = get_object_or_404(Post.objects.select_related('author').prefetch_related('attachments'), pk=pk)
    except Exception as e:
        # [취약점] A10: Mishandling of Exceptional Conditions
        # 예외 내용을 그대로 화면에 렌더링
        # DB 에러나 코드 에러가 발생하면 내부 로직이 적나라하게 드러남
        return HttpResponse(f"Error Occurred: {str(e)}", status=500)

    # 댓글은 2순위라 UI만 최소 제공 (작성 기능은 다음 단계에서 확장 가능)
    return render(request, 'board/post_detail.html', {'post': post})


@login_required
def post_create_view(request):
    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.save()
            return redirect('post_detail', pk=post.pk)
    else:
        form = PostForm()
    return render(request, 'board/post_form.html', {'form': form})


# -------- 지식인 Q&A --------
def question_list_view(request):
    questions = Question.objects.select_related('author', 'accepted_answer')
    return render(request, 'board/question_list.html', {'questions': questions})


def question_detail_view(request, pk):
    question = get_object_or_404(
        Question.objects.select_related('author', 'accepted_answer').prefetch_related('answers__author'),
        pk=pk,
    )
    answer_form = AnswerForm()
    return render(
        request,
        'board/question_detail.html',
        {'question': question, 'answer_form': answer_form},
    )


@login_required
def question_create_view(request):
    if request.method == 'POST':
        form = QuestionForm(request.POST)
        if form.is_valid():
            q = form.save(commit=False)
            q.author = request.user
            q.save()
            return redirect('question_detail', pk=q.pk)
    else:
        form = QuestionForm()
    return render(request, 'board/question_form.html', {'form': form})


@login_required
@require_POST
def answer_create_view(request, pk):
    question = get_object_or_404(Question, pk=pk)
    form = AnswerForm(request.POST)
    if form.is_valid():
        ans = form.save(commit=False)
        ans.question = question
        ans.author = request.user
        ans.save()
    return redirect('question_detail', pk=question.pk)


@login_required
@require_POST
def accept_answer_view(request, question_pk, answer_pk):
    """
    답변 채택 로직 (포인트 지급은 3번 금융 시스템이 빠져 있으므로 구현하지 않음).
    채택은 질문자만 가능.
    """
    question = get_object_or_404(Question, pk=question_pk)
    if request.user.id != question.author_id:
        return redirect('question_detail', pk=question.pk)

    answer = get_object_or_404(Answer, pk=answer_pk, question=question)
    question.accepted_answer = answer
    question.is_solved = True
    question.save(update_fields=['accepted_answer', 'is_solved'])
    return redirect('question_detail', pk=question.pk)


# -------- 댓글(골격) --------
@login_required
@require_POST
def comment_create_view(request):
    """
    Generic 댓글 생성 (대상: post/question/answer).
    UI는 최소로 두고, 이후 단계에서 상세/대댓글/삭제/수정 확장.
    """
    target_model = request.POST.get('target_model')
    object_id = request.POST.get('object_id')
    content = request.POST.get('content', '').strip()
    parent_id = request.POST.get('parent_id')

    model_map = {
        'post': Post,
        'question': Question,
        'answer': Answer,
    }
    Model = model_map.get(target_model)
    if not Model or not object_id or not content:
        return redirect('board_home')

    target_obj = get_object_or_404(Model, pk=object_id)
    ctype = ContentType.objects.get_for_model(Model)

    parent = None
    if parent_id:
        parent = get_object_or_404(Comment, pk=parent_id)

    Comment.objects.create(
        author=request.user,
        content=content,
        parent=parent,
        content_type=ctype,
        object_id=target_obj.pk,
    )

    # 작성 후에는 referer로 복귀
    return redirect(request.META.get('HTTP_REFERER', '/'))

