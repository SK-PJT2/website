# SafePoint Market

중고거래와 포인트 금융 시스템이 결합된 'SafePoint Market' 프로젝트입니다. 이 프로젝트는 Docker 기반의 3-티어 아키텍처(Nginx-Gunicorn-MariaDB)로 구성되어 있으며, GitHub Actions를 통해 CI/CD가 자동화되어 있습니다.

---

## 🛠️ Tech Stack

- **Framework**: Django 4.2+
- **Web Server**: Nginx
- **WAS**: Gunicorn
- **Database**: MariaDB 10.6
- **Container**: Docker & Docker-compose
- **CI/CD**: GitHub Actions (Docker Hub Push)

---

## 🚀 로컬 개발 환경 실행 가이드

### 사전 준비 사항

1.  **Docker & Docker Compose**: 로컬 시스템에 최신 버전의 Docker와 Docker Compose를 설치해야 합니다.
2.  **환경 변수 파일 (`.env`) 생성**:
    - 프로젝트 루트 디렉토리에 `.env` 파일을 생성하여 내용 복붙

### 프로젝트 최초 실행

터미널을 열고 프로젝트의 루트 디렉토리에서 아래 명령어들을 **순서대로** 실행하세요.

**1. Docker 컨테이너 빌드 및 실행**
```bash
docker-compose up --build -d
```
> `web`(Nginx), `was`(Django), `db`(MariaDB) 3개의 서비스 컨테이너가 백그라운드에서 실행됩니다.

**2. 데이터베이스에 마이그레이션 적용**
```bash
docker-compose exec was python manage.py migrate
```
> 생성된 마이그레이션 파일을 포함하여 모든 변경사항을 데이터베이스에 적용합니다.

**4. 관리자 계정 생성**
```bash
docker-compose exec was python manage.py createsuperuser
```
> 안내에 따라 관리자 페이지에 로그인할 계정 정보를 입력합니다.

**4. 접속 확인**
- **웹사이트**: [http://localhost](http://localhost)
- **관리자 페이지**: [http://localhost/admin](http://localhost/admin)

> 웹 브라우저에서 접속하여 Django 기본 환영 페이지와 관리자 로그인 페이지가 정상적으로 보이는지 확인합니다.

---

## ⚙️ 주요 Docker 명령어

- **모든 서비스 시작 (백그라운드)**: `docker-compose up -d`
- **모든 서비스 중지 및 컨테이너 삭제**: `docker-compose down`
- **실시간 로그 확인**: `docker-compose logs -f was`
- **컨테이너 내부 쉘 접속**: `docker-compose exec was bash`

---

## 🔄 CI/CD (지속적 통합/배포)

- `main` 브랜치에 코드가 푸시되면, GitHub Actions가 자동으로 실행됩니다.
- 워크플로우는 `Dockerfile`을 기반으로 새로운 Docker 이미지를 빌드하여 Docker Hub의 `[DOCKER_USERNAME]/safepoint-market:latest` 태그로 푸시합니다.
- **주의**: 이 기능을 사용하려면 GitHub 저장소의 `Settings > Secrets and variables > Actions`에 `DOCKER_USERNAME`과 `DOCKER_PASSWORD`가 등록되어 있어야 합니다.
