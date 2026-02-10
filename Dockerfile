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

# Gunicorn 서버 실행
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "config.wsgi:application"]