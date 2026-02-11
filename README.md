# SafePoint Market 🛡️💸 (Vulnerable Web App)

**SafePoint Market**은 OWASP Top 10 (2025) 취약점을 학습하고 실습하기 위해 의도적으로 취약하게 설계된 중고거래 웹 애플리케이션입니다.
Docker 기반의 3-Tier 아키텍처(Nginx-Django-MariaDB)로 구성되어 있으며, 사용자는 이 환경에서 다양한 공격 기법을 안전하게 테스트해볼 수 있습니다.

---

## 🛠️ Tech Stack

- **Framework**: Django 4.2+
- **Web Server**: Nginx
- **WAS**: Daphne (ASGI)
- **Database**: MariaDB 10.6
- **Container**: Docker & Docker-compose
- **CI/CD**: GitHub Actions

### 🏗️ Architecture

```mermaid
graph LR
    User[👤 User] -->|HTTP/WS| Nginx[🌐 Nginx (Web Server)]
    subgraph "🐳 Docker Host"
        Nginx -->|Reverse Proxy| Daphne[⚡ Daphne (ASGI)]
        Daphne -->|SQL| MariaDB[🗄️ MariaDB (Database)]
    end
    
    style User fill:#f9f,stroke:#333,stroke-width:2px
    style Nginx fill:#bbf,stroke:#333,stroke-width:2px
    style Daphne fill:#bfb,stroke:#333,stroke-width:2px
    style MariaDB fill:#fbf,stroke:#333,stroke-width:2px
```

---

## 🚀 빠른 시작 가이드 (Quick Start)

### 1. 실행 (Run)
터미널에서 아래 명령어로 컨테이너를 빌드하고 실행하세요.
```bash
docker-compose up --build -d
```

### 2. 초기 세팅 (Setup)
데이터베이스 마이그레이션을 통해 테이블과 **테스트 데이터(계정, 상품, 글)**를 생성합니다.
```bash
docker-compose exec was python manage.py migrate
```
> **Note**: 이 명령어가 실행되면 `admin`, `victim`, `attacker` 등 테스트 계정과 상품, 채팅방, 게시글이 자동으로 생성됩니다.

### 3. 접속 (Access)
- **웹사이트**: [http://localhost](http://localhost)
- **관리자 페이지**: [http://localhost/admin](http://localhost/admin)

---

## 👥 테스트 계정 정보 (Test Accounts)

모든 비밀번호 패턴은 `아이디 + 123` 입니다.

| 역할 | 아이디 | 비밀번호 | 설명 |
| :--- | :--- | :--- | :--- |
| **공격자** | `attacker` | `attacker123` | 해커 빙의용 계정 |
| **피해자** | `victim` | `victim123` | 일반 판매자/구매자 |
| **슈퍼유저** | `admin` | `admin123` | 사이트 관리자 |
| **부자유저** | `rich_user` | `rich123` | 100만 포인트 보유 |
| **거지유저** | `poor_user` | `poor123` | 500 포인트 보유 |

---

## ⚠️ 구현된 취약점 (Vulnerability Showcase)

이 프로젝트에는 **OWASP Top 10 (2025)** 기반의 주요 취약점들이 곳곳에 숨겨져 있습니다.
상세한 구현 원리는 **[OWASP_Top_10_Vulnerability_Implementation_Guide.md](./OWASP_Top_10_Vulnerability_Implementation_Guide.md)**를 참조하세요.

| ID | 취약점 이름 (Vulnerability) | 위치/설명 |
| :--- | :--- | :--- |
| **A01** | **Broken Access Control** | `chat/views.py`: 남의 채팅방 훔쳐보기 (IDOR) |
| **A02** | **Security Misconfiguration** | `settings.py`: `DEBUG=True` 및 `ALLOWED_HOSTS=['*']` |
| **A04** | **Cryptographic Failures** | `accounts/views.py`: 2차 비밀번호 평문 저장 |
| **A05** | **Injection (SQLi)** | `board/views.py`: 게시판 검색창 SQL Injection |
| **A06** | **Insecure Design** | `market/views.py`: 상품 가격 조작 (마이너스 가격) |
| **A07** | **Authentication Failures** | `accounts/views.py`: 로그인 실패 메시지 상세 노출 (User Enumeration) |
| **A08** | **Integrity Failures** | `board/views.py`: 첨부파일 검증 부재 (Web Shell 업로드 가능) |
| **A09** | **Security Logging Failures** | `accounts/views.py`: 로그인 시 비밀번호를 로그에 남김 |
| **A10** | **Exception Handling** | `board/views.py`: 에러 발생 시 Stack Trace 노출 |

---

## ⚔️ 공격 실습 가이드 (Attack Guide)

실제로 이 취약점들을 어떻게 공격하는지는 **[Attack_Examples.md](./Attack_Examples.md)** 파일에 단계별로 정리되어 있습니다.
`attacker` 계정으로 로그인하여 직접 실습해 보시길 권장합니다.

**대표적인 공격 시나리오:**
1. **IDOR**: URL의 방 번호를 바꿔서 남의 대화 훔쳐보기
2. **SQL Injection**: 검색창에 `' OR '1'='1` 입력하여 비밀글 탈취
3. **Logic Flaw**: -50,000원짜리 상품을 구매하여 돈 복사하기

---

## ⚙️ 주요 Docker 명령어

- **재시작 (코드 수정 반영)**: `docker-compose restart was`
- **로그 확인 (로그인 비밀번호 노출 확인용)**: `docker-compose logs -f was`
- **DB 초기화 및 데이터 복구**:
  ```bash
  docker-compose exec was python manage.py flush --no-input
  docker-compose exec was python manage.py migrate
  ```

---

## ⚠️ Disclaimer

본 프로젝트는 **정보 보안 교육 및 학습 목적**으로 제작되었습니다.
반드시 본인의 로컬 환경(`localhost`)에서만 테스트하십시오.
