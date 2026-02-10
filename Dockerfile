# 1. 최신 안정 버전의 Base Image 사용
FROM python:3.10-slim

# 2. Docker 환경에 권장되는 ENV 변수 추가
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# 3. 안정적인 한국 미러를 사용하고 의존성 설치
RUN sed -i 's/deb.debian.org/ftp.kr.debian.org/g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    default-libmysqlclient-dev \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /app

# requirements.txt 먼저 복사하여 빌드 캐시 활용
COPY ./requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# 4. 필요한 소스 코드만 정확히 복사
COPY ./was /app/was
COPY ./config /app/config

# Gunicorn 실행 포트 노출
EXPOSE 8000

# Gunicorn 서버 실행
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "config.wsgi:application"]