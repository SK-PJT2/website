# 1. full 버전의 안정적인 Base Image 사용
FROM python:3.10

# 2. Docker 환경에 권장되는 ENV 변수 추가
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# 작업 디렉토리 설정
WORKDIR /app

# requirements.txt 먼저 복사하여 빌드 캐시 활용
COPY ./requirements.txt /app/
# 3. --no-cache-dir 옵션 추가 및 pip 업그레이드
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4. .dockerignore에 명시된 파일을 제외하고 모든 파일 복사
COPY . /app/

# Gunicorn 실행 포트 노출
EXPOSE 8000

# 기존 gunicorn 실행 명령어를 주석 처리하거나 삭제하고 아래 내용을 추가합니다.
# CMD ["gunicorn", "--bind", "0.0.0.0:8000", "config.wsgi:application"]

# Daphne로 ASGI 어플리케이션 실행
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "config.asgi:application"]