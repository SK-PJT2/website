<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# [https://owasp.org/Top10/2025/](https://owasp.org/Top10/2025/)

2025년 owasp top 10에 대해서 알고싶은데, 저 링크를 통해서 해당 내용과 어떤 코드가 취약점이 있는지, 어떻게 해결하는지 세세하게 전부 알려줘.

OWASP Top 10:2025는 2025년 기준으로 전 세계 웹 애플리케이션에서 가장 많이, 가장 치명적으로 나타나는 취약점 10가지를 정리한 목록입니다.[^1_1]
2025 리스트는 아래와 같습니다.[^1_2]

1. A01:2025 – Broken Access Control (취약한 접근 제어)
2. A02:2025 – Security Misconfiguration (보안 설정 오류)
3. A03:2025 – Software Supply Chain Failures (소프트웨어 공급망 실패)
4. A04:2025 – Cryptographic Failures (암호학 실패)
5. A05:2025 – Injection (인젝션)
6. A06:2025 – Insecure Design (안전하지 않은 설계)
7. A07:2025 – Authentication Failures (인증 실패)
8. A08:2025 – Software or Data Integrity Failures (소프트웨어/데이터 무결성 실패)
9. A09:2025 – Security Logging \& Alerting Failures (보안 로깅 및 알림 실패)
10. A10:2025 – Mishandling of Exceptional Conditions (예외 상황 처리 미흡)[^1_1]

아래에서는 각 항목마다:

- 개념 요약 (OWASP 2025 기준 정리)
- 대표적인 취약 코드 패턴
- 안전한 코드/설계로 고치는 방법

순서로 설명합니다. 코드 예시는 이해를 돕기 위한 예제이며, 실제 OWASP 문서의 예시 코드가 아니라 일반적인 취약 패턴을 기반으로 만든 것입니다(즉, “원리 설명용 예시 코드”입니다).

***

## A01: Broken Access Control (취약한 접근 제어)[^1_3][^1_4]

### 개념 요약

- 접근 제어(Authorization)를 제대로 구현하지 못해, 사용자가 “권한 밖의 데이터·기능”에 접근할 수 있는 상태를 말합니다.
- 2025년에도 1위를 유지하며, 테스트된 애플리케이션 100%에서 어떤 형태로든 발견될 정도로 매우 흔합니다.[^1_4]
- 대표 예: IDOR(직접 객체 참조), 수평/수직 권한 상승, 서버 사이드에서 권한 체크 없이 클라이언트 신호만 믿는 경우, SSRF·CSRF와 얽힌 권한 우회 등.[^1_3][^1_4]


### 취약한 코드 예시

#### 1) IDOR – URL 파라미터만으로 리소스 식별

```python
# /orders/view?orderId=123
@app.route("/orders/view")
def view_order():
    order_id = request.args["orderId"]
    # 로그인한 사용자와 무관하게 order_id 로만 조회
    order = Order.query.filter_by(id=order_id).first()
    return render_template("order.html", order=order)
```

- 문제: 로그인한 사용자와 order의 소유자 관계를 확인하지 않으므로, 공격자가 `orderId=124` 등으로 바꾸어 다른 사람의 주문을 열람 가능(IDOR).


#### 2) 관리자 기능을 단순한 UI 숨김으로만 막음

```javascript
// 클라이언트에서만 관리자 메뉴 숨기기
if (currentUser.role !== 'ADMIN') {
  document.querySelector('#adminMenu').style.display = 'none';
}

// 서버 코드
app.post('/admin/deleteUser', (req, res) => {
  const userId = req.body.userId
  // 서버에서 권한 체크 없음
  deleteUser(userId)
  res.send('ok')
})
```

- 문제: UI에서 버튼을 숨겨도, 공격자는 직접 POST 요청을 보내면 누구나 관리자 API를 호출 가능.


### 안전한 설계/코드

#### 1) 서버에서 “소유자 확인”을 강제

```python
@app.route("/orders/view")
@login_required
def view_order():
    order_id = request.args["orderId"]
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id   # 소유자 확인
    ).first_or_404()
    return render_template("order.html", order=order)
```


#### 2) 중앙 집중식 권한 체크 (RBAC/ABAC)

```python
def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.post('/admin/deleteUser')
@login_required
@require_role('ADMIN')
def delete_user_admin():
    ...
```


#### 3) 체크리스트

- 모든 민감 기능/리소스는 **서버 측**에서 권한 검사를 수행할 것
- ID 값(URL, body, 헤더 등)이 들어오는 곳에서는 항상 “현재 사용자가 이 리소스의 소유자인가?” 검사
- 접근 제어 로직을 코드 여기저기에 흩뿌리지 말고, 필터/미들웨어/Interceptor 등 중앙에서 관리
- “링크를 숨겨서” 막는 패턴(보안 by obscurity) 금지
- SSRF, CSRF, CORS 등도 접근 제어 맥락에서 재검토 (내부 자원 우회 접근 방지)[^1_4][^1_3]

***

## A02: Security Misconfiguration (보안 설정 오류)[^1_5][^1_6]

### 개념 요약

- 시스템·앱·클라우드 서비스의 설정이 잘못되어 취약점이 생기는 경우 전체입니다.[^1_6][^1_5]
- 2021년 5위에서 2025년에는 2위까지 상승할 정도로, “모든 앱이 어느 정도는 가지고 있는 문제”로 드러났습니다.[^1_5]
- 예: 기본 계정/비번 유지, 디렉터리 리스팅, 디버그 모드, 과도하게 열린 클라우드 버킷, 보안 헤더 미설정, 불필요한 서비스/포트 활성화 등.[^1_7][^1_5]


### 취약한 코드/설정 예시

#### 1) 프로덕션에서 디버그 모드 ON

```python
# app.py
app.run(debug=True)  # 스택 트레이스, 환경변수 노출
```


#### 2) 기본 계정 그대로 사용

```yaml
# application.properties
spring.datasource.username=admin
spring.datasource.password=admin   # 그대로 배포
```


#### 3) 보안 헤더 미설정 (XSS, clickjacking 위험)

```nginx
# 아무 헤더 없음
location / {
    proxy_pass http://app;
}
```


### 안전한 설계/코드

- **프로덕션과 개발 환경 분리**
    - prod에서는 debug/log level 최소화, 상세 stack trace는 로그에만 남기고 사용자에게는 일반 메시지만 노출.
- **보안 헤더 설정 (웹 서버 또는 앱 레벨)**

```nginx
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self';";
```

- **기본 계정/기본 비밀번호 제거**
    - 초기 설정 직후 반드시 변경, 또는 기본 계정 자체를 비활성화.
- **불필요한 서비스/포트/샘플 앱 제거**
- **IaC(Terraform 등)와 CIS Benchmark/클라우드 벤더 Best Practice로 자동 검증**[^1_7][^1_5]

***

## A03: Software Supply Chain Failures (소프트웨어 공급망 실패)[^1_8][^1_9]

### 개념 요약

- 이전의 “취약하고 오래된 컴포넌트” 범주를 확장해, **의존 라이브러리, 빌드/배포 파이프라인, 패키지 레지스트리, 컨테이너 이미지 등 공급망 전체**에서 발생하는 문제를 포괄합니다.[^1_9][^1_10]
- 악성 패키지, 타이포스쿼팅, 취약한/업데이트 안 되는 라이브러리, 해킹된 CI/CD 서버, 서명 없는 업데이트 등.[^1_11][^1_8]


### 취약한 코드/구성 예시

#### 1) 무분별한 의존성 추가

```json
// package.json
"dependencies": {
  "left-pad": "*",             // 버전 상한선 없음
  "some-strange-lib": "latest" // 내부 검증 안 된 서드파티
}
```

- 문제: 레포가 탈취되거나 악성 버전이 올라가면 바로 영향을 받음.


#### 2) 빌드 서버에 대한 접근 제어 부재

```bash
# CI 서버에서 빌드 스크립트
pip install -r requirements.txt  # 내부 프록시/미러 없이 인터넷에서 직접 설치
./deploy.sh                      # 빌드/배포 스크립트에 코드 리뷰 없음
```

- 문제: requirements.txt가 악성 패키지를 가리키거나, CI 자격증명이 탈취되면 악성 코드가 공식 바이너리로 배포될 수 있음.


### 안전한 설계/코드

- **SBOM(Software Bill of Materials) 관리**
    - 모든 의존성(직접/간접)을 인벤토리로 관리, SCA 도구로 취약점 상시 스캔.[^1_10]
- **사설 레지스트리/미러 사용 및 화이트리스트**
    - npm/pypi/maven 중앙 저장소에서 임의의 패키지 직접 받지 말고, 검증된 패키지만 내부 미러에 두고 사용.
- **버전 고정 및 자동 업데이트 전략**

```json
"dependencies": {
  "express": "^4.21.0"   // 검증된 범위 내에서만 업데이트
}
```

- **CI/CD 보안 강화**
    - 최소 권한 원칙, 이중 승인(한 사람이 코드 작성+배포까지 단독 수행 불가), 시크릿 안전 보관.[^1_9][^1_10]
- **서명 검증 및 무결성 체크**
    - 릴리즈 아티팩트/컨테이너 이미지 서명, 해시 검증 적용.

***

## A04: Cryptographic Failures (암호학 실패)[^1_12][^1_13]

### 개념 요약

- 암호를 안 쓰거나, 약한 알고리즘/키/구성, 잘못된 구현 등으로 민감 데이터 보호에 실패한 경우.[^1_13][^1_12]
- 예: 평문 비밀번호 저장, MD5/SHA1, 하드코딩된 키, 잘못된 무작위수 생성, HTTPS 미사용, 인증 없이 암호화만 하는 경우 등.[^1_14][^1_13]


### 취약한 코드 예시

#### 1) 평문 또는 약한 해시로 비밀번호 저장

```python
# 취약
password_hash = hashlib.md5(password.encode()).hexdigest()
store_in_db(username, password_hash)
```


#### 2) 하드코딩된 암호 키

```java
public class CryptoUtil {
    private static final String SECRET_KEY = "1234567890123456"; // 코드에 박힌 키

    public static String encrypt(String data) { ... }
}
```


#### 3) 예측 가능한 랜덤 값으로 토큰 생성

```javascript
// Math.random() 기반 세션/토큰
const token = Math.random().toString(36).substring(2);
```


### 안전한 설계/코드

#### 1) 검증된 알고리즘과 키 관리

- 비밀번호: **bcrypt / Argon2 / PBKDF2** 등 적절한 워크 팩터를 가진 해시 사용

```python
from passlib.hash import bcrypt

hashed = bcrypt.hash(password)
bcrypt.verify(input_password, hashed)
```

- 암호화: AES-GCM 등 인증된 암호화(AEAD) 알고리즘 사용, 랜덤 IV/Nonce 필수.[^1_13]


#### 2) 키·시크릿은 코드에 넣지 말고 안전한 저장소 사용

- 클라우드 KMS, Vault, OS 시크릿 스토어, 환경변수+권한 통제 등.


#### 3) 안전한 난수 생성기 사용

```python
import secrets
token = secrets.token_urlsafe(32)
```


#### 4) HTTPS 강제 및 인증서/체인 검증

- TLS 1.2 이상, 인증서 유효성/체인/도메인 검증 필수.[^1_14][^1_13]

***

## A05: Injection (인젝션)[^1_15][^1_16]

### 개념 요약

- 신뢰할 수 없는 입력이 SQL/OS/LDAP/NoSQL/템플릿 엔진 등의 인터프리터로 그대로 들어가 명령이 변조되는 취약점입니다.[^1_17][^1_15]
- SQLi, Command Injection, LDAP/NoSQL Injection, Template Injection 등.
- 여전히 치명적이며, 많은 앱에서 어떤 형태로든 발견됩니다.[^1_17]


### 취약한 코드 예시

#### 1) SQL Injection (파라미터 바인딩 없음)

```python
username = request.args["username"]
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)  # ' OR '1'='1 등으로 우회 가능
```


#### 2) OS Command Injection

```python
filename = request.args["file"]
os.system(f"ls {filename}")  # ; rm -rf / 등 삽입 가능
```


### 안전한 설계/코드

#### 1) Prepared Statement / 파라미터 바인딩

```python
username = request.args["username"]
cursor.execute(
    "SELECT * FROM users WHERE username = %s",
    (username,)
)
```


#### 2) OS 명령 호출을 피하거나, 인자 분리

```python
import subprocess

subprocess.run(["ls", filename])  # 쉘 파싱 없이 인자 배열 전달
```


#### 3) 화이트리스트 기반 입력 검증

- ID는 숫자만, 상태값은 열거형만 허용 등.


#### 4) ORM/쿼리빌더 사용

- 직접 문자열로 쿼리 이어붙이기 지양.[^1_16][^1_17]

***

## A06: Insecure Design (안전하지 않은 설계)[^1_18][^1_19]

### 개념 요약

- 코드 버그가 아니라 **설계 단계에서 보안 요구 사항·위협 모델링·비즈니스 로직 통제**가 부족해서 생기는 취약점입니다.[^1_19]
- 예: 로그인은 잘 구현했지만, 비밀번호 시도 횟수 제한이 없다거나, 환불 로직에 한도가 없어 무한 환불 가능, 워크플로우 스킵 가능 등.[^1_20][^1_21]


### 취약한 설계/코드 예시

#### 1) 비즈니스 로직 결함 (환불 한도 없음)

```python
def refund(order_id, amount):
    order = get_order(order_id)
    # 이미 환불했는지, 한도 초과인지 체크 없음
    order.balance += amount
```


#### 2) 레이스 컨디션을 고려하지 않은 포인트 적립

```python
# 동시에 여러 요청이 들어오면 포인트가 중복 적립될 수 있음
def add_points(user_id, points):
    user = get_user(user_id)
    user.points += points
    save(user)
```


### 안전한 설계/코드

- **Threat Modeling(STRIDE 등) 수행**
    - 기능 설계 시 공격 시나리오(오용·남용 케이스)를 함께 정의.[^1_20][^1_19]
- **보안 요구사항을 명시적 요구사항으로 포함**
    - 예: “계정 잠금 정책”, “환불 한도”, “승인 워크플로우”, “속도 제한” 등.
- **디자인 패턴**
    - RBAC/ABAC, 레이트 리미팅, 세션 관리, 감사 로그, 트랜잭션 관리 등 공통 패턴 사용.
- **테스트 관점에서 비즈니스 로직 의도 검증**
    - 단위/통합 테스트에 오용 케이스 포함 (한도 초과, 중복 요청, 순서 꼬이기 등).[^1_18][^1_20]

***

## A07: Authentication Failures (인증 실패)[^1_22][^1_23]

### 개념 요약

- 사용자 신원을 확인하는 과정(로그인, 세션, 패스워드 리셋 등)에 취약점이 있어, 공격자가 다른 사용자로 가장할 수 있는 상황입니다.[^1_23][^1_22]
- 약한/기본 비밀번호 허용, 취약한 비밀번호 복구, 세션 토큰 노출, 세션 고정, MFA 부재/우회 등.[^1_22]


### 취약한 코드 예시

#### 1) 약한 비밀번호 정책과 평문 저장

```python
if len(password) < 4:
    raise ValueError("too short")  # 사실상 의미 없음

store_in_db(username, password)     # 평문 저장
```


#### 2) 세션 토큰을 URL에 노출

```python
# 로그인 성공 시
session_id = create_session(user.id)
return redirect(f"/dashboard?sid={session_id}")  # 링크 공유 시 세션 유출
```


#### 3) 세션 재발급 없음 (세션 고정)

```python
# 로그인 전후 같은 세션 ID 재사용
# 공격자가 기존 세션 ID를 알고 있으면 로그인 이후에도 그대로 사용 가능
```


### 안전한 설계/코드

- **강력한 비밀번호 저장**
    - bcrypt/Argon2 등, 적절한 솔트·워크 팩터.
- **비밀번호 정책·크리덴셜 재사용 방지**
    - 너무 복잡한 규칙보다는 길이+블랙리스트, 크리덴셜 스터핑 방지.[^1_23]
- **세션 관리 원칙**
    - 로그인 후 **새 세션 ID 발급**, 로그아웃/타임아웃 시 세션 무효화.
    - 세션 ID를 URL, HTML 숨은 필드에 넣지 말고, HttpOnly Secure 쿠키 사용.
- **MFA (가능하면 패스키/웹Authn 등 강력한 방법)**
- **안전한 비밀번호 복구**
    - 이메일/문자 링크 기반 토큰 + 짧은 만료시간, KBA(“어머니 성함?” 같은 질문) 금지.[^1_22][^1_23]

***

## A08: Software or Data Integrity Failures (소프트웨어/데이터 무결성 실패)[^1_24][^1_25]

### 개념 요약

- “이 데이터/코드/업데이트는 신뢰할 수 있다”는 가정이 깨지는 경우입니다.[^1_25]
- 서명/무결성 검증 없이 업데이트나 플러그인, 스크립트, 직렬화 데이터 등을 받아들일 때 발생.
- 예: 신뢰할 수 없는 출처의 플러그인 로딩, 서명 없는 auto-update, 직렬화 데이터 무검증 역직렬화 등.[^1_26][^1_25]


### 취약한 코드 예시

#### 1) 서명·무결성 검증 없이 업데이트 다운로드

```python
# 서버에서 내려주는 update.zip 을 그냥 받아 실행
url = "https://updates.example.com/update.zip"
data = requests.get(url).content
open("/opt/app/update.zip", "wb").write(data)
# 바로 unzip 후 실행
```


#### 2) 신뢰 안 되는 데이터 역직렬화

```java
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
Object obj = in.readObject(); // 출처·타입 검증 없음 (RCE 위험)
```


### 안전한 설계/코드

- **서명 검증 필수**
    - 업데이트/플러그인/스크립트/컨테이너 이미지에 대해 서명(서명키 관리 포함) 및 해시 검증.[^1_25]
- **역직렬화 최소화, 안전한 포맷 사용**
    - 가능하면 JSON 등 단순 포맷 + 스키마 검증, 폴리모픽 역직렬화 금지.
- **CI/CD에서 무결성 검사를 단계마다 수행**
    - 플러그인/스테이지마다 해시·서명 검증, 권한 분리.[^1_27][^1_24]

***

## A09: Security Logging \& Alerting Failures (보안 로깅 및 알림 실패)[^1_28][^1_29]

### 개념 요약

- 공격·이상 행위에 대한 로깅/모니터링/알림이 부족해서, 침해가 발생해도 오랫동안 모르는 상태를 말합니다.[^1_28]
- 2025 리스트에서도 9위를 유지하며, CVE 데이터에서는 과소 표현되지만, 인시던트 대응·포렌식에서 매우 중요합니다.[^1_29][^1_28]


### 취약한 코드 예시

#### 1) 로그인 실패/중요 액션 로그 없음

```python
def login():
    user = find_user(request.form['id'])
    if not user or not check_pw(...):
        # 실패 로그 없음
        return "Invalid credentials", 401
```


#### 2) 민감 정보 로그에 그대로 기록

```python
logger.error(f"Login failed for {user.email} with password={password}")
# 비밀번호/토큰을 로그에 남김
```


### 안전한 설계/코드

- **무엇을 반드시 로그로 남길지 정의**
    - 로그인 성공/실패, 비밀번호 변경, 권한 변경, 관리자 액션, 예외/에러 등.[^1_28]
- **표준화된 로그 포맷**
    - 타임스탬프, 요청 ID, 사용자 ID/주체, IP, 액션, 결과…
- **민감 정보 마스킹**
    - 비밀번호, 토큰, 카드번호, 주민번호 등은 절대 로그에 저장 금지.[^1_30][^1_28]
- **중앙 집계 + 알림**
    - SIEM, APM, 클라우드 로그 서비스 사용, 임계치 기반 알림/대응 프로세스 구축.

***

## A10: Mishandling of Exceptional Conditions (예외 상황 처리 미흡)[^1_31][^1_32]

### 개념 요약

- 2025년 새로 추가된 카테고리로, 예외/에러/비정상 상태를 제대로 “방지·감지·대응”하지 못해 보안 문제가 되는 경우입니다.[^1_32][^1_1]
- 대표적인 CWE:
    - 민감 정보를 포함한 에러 메시지 노출(CWE-209),
    - 누락된 파라미터/권한 처리 실패(CWE-234/274),
    - NULL 포인터 dereference, divide by zero, fail-open 등.[^1_31][^1_32]


### 취약한 코드 예시

#### 1) 스택 트레이스를 그대로 사용자에게 노출

```java
try {
    processPayment(request);
} catch (Exception e) {
    e.printStackTrace();                 // 콘솔
    response.getWriter().println(e);     // 사용자에게 내부 예외 문자열 출력
}
```


#### 2) 실패 시 “열어주는” fail-open 패턴

```python
def authorize(user, action):
    try:
        return acl_check(user, action)
    except Exception:
        # 권한 체크 실패하면 그냥 허용 (fail-open)
        return True
```


#### 3) 리소스 정리가 안 되는 예외 처리 (DoS 위험)

```python
def upload_file(f):
    tmp = open('/tmp/file', 'wb')
    try:
        tmp.write(f.read())
    except Exception:
        # close/cleanup 없이 return -> 핸들 누수, 디스크 고갈
        return "error"
```


### 안전한 설계/코드

- **Fail-Closed 기본 원칙**
    - 보안 관련 기능은 에러 시 **허용이 아니라 거부**가 기본.[^1_33][^1_32]
- **전역/로컬 예외 처리 전략 수립**
    - 각 계층(컨트롤러/서비스/리포지토리)에서 예상 가능한 예외는 로컬에서 처리,
    - 그 외는 전역 예외 핸들러로 모아서 표준화된 에러 응답 + 로그만 남기기.

```python
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error("Unhandled error", exc_info=e)
    return {"message": "서버 오류가 발생했습니다."}, 500
```

- **민감 정보 제거된 에러 메시지**
    - 사용자에겐 간단하고 일반적인 메시지만, 세부 내용은 서버 로그에만 남김.[^1_32]
- **리소스 정리 및 제한**
    - finally 블록 또는 context manager(`with`)로 파일·소켓·락 해제,
    - Rate limit, timeout, circuit breaker로 비정상 트래픽/장애 전파 차단.[^1_33][^1_32]

***

## 마무리: 실무에서 어떻게 적용할지

OWASP Top 10:2025는 “이론 목록”이라기보다, 실제로 개발 조직이 다음과 같이 활용하는 것이 좋습니다.

1. **코드/설계 리뷰 체크리스트로 사용**
    - PR 템플릿이나 설계 리뷰 템플릿에 A01~A10 항목을 매핑해서 “이 기능에서 해당 이슈 없나?”를 반복적으로 확인.
2. **정기적인 교육 + 취약 코드/안전 코드 비교 학습**
    - 위에 나온 것처럼 “취약 패턴 vs 안전 패턴”을 팀 내 언어/프레임워크에 맞게 정리해 개발 가이드로 삼기.
3. **테스트/도구와 연계**
    - SAST/DAST/SCA/SCA + CI 파이프라인에서 각 항목과 연결되는 규칙을 활성화하고, 위반 시 빌드 실패 등 정책을 명확히.
4. **로그·모니터링·예외 처리 일원화**
    - A09/A10은 특히 코드가 아니라 “플랫폼/아키텍처 레벨”에서 통합적으로 설계해야 효과가 큽니다.

원하면, 사용 중인 언어/프레임워크(예: Spring Boot, Django, Node.js/Express, NestJS 등)에 맞춰
각 항목별로 “그 스택에서 자주 나오는 취약 코드 패턴 + 구체적인 방어 코드 템플릿”만 따로 정리해 줄 수도 있습니다.
<span style="display:none">[^1_100][^1_101][^1_102][^1_34][^1_35][^1_36][^1_37][^1_38][^1_39][^1_40][^1_41][^1_42][^1_43][^1_44][^1_45][^1_46][^1_47][^1_48][^1_49][^1_50][^1_51][^1_52][^1_53][^1_54][^1_55][^1_56][^1_57][^1_58][^1_59][^1_60][^1_61][^1_62][^1_63][^1_64][^1_65][^1_66][^1_67][^1_68][^1_69][^1_70][^1_71][^1_72][^1_73][^1_74][^1_75][^1_76][^1_77][^1_78][^1_79][^1_80][^1_81][^1_82][^1_83][^1_84][^1_85][^1_86][^1_87][^1_88][^1_89][^1_90][^1_91][^1_92][^1_93][^1_94][^1_95][^1_96][^1_97][^1_98][^1_99]</span>

<div align="center">⁂</div>

[^1_1]: https://owasp.org/Top10/2025/0x00_2025-Introduction/

[^1_2]: https://owasp.org/Top10/2025/en/

[^1_3]: https://orca.security/resources/blog/owasp-top-10-2025-key-changes/

[^1_4]: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/

[^1_5]: https://blog.intelligencex.org/security-misconfiguration-owasp-a02-2025-complete-guide

[^1_6]: https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/

[^1_7]: https://www.linkedin.com/pulse/owasp-a022025-security-misconfiguration-cyberhorizon-defentech-6jtuc

[^1_8]: https://blog.intelligencex.org/software-supply-chain-failures-owasp-a03-2025-complete-guide

[^1_9]: https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/

[^1_10]: https://www.endorlabs.com/learn/owasp-top-10-adds-a03-2025-software-supply-chain-failures

[^1_11]: https://www.seal.security/blog/owasp-named-software-supply-chain-failures-now-its-time-to-fix-them

[^1_12]: http://www.indusface.com/learning/owasp-top-10-cryptographic-failures/

[^1_13]: https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/

[^1_14]: https://www.linkedin.com/pulse/owasp-a042025-cryptographic-failures-cyberhorizon-defentech-fxavc

[^1_15]: https://www.linkedin.com/pulse/owasp-a052025-injection-cyberhorizon-defentech-de6nc

[^1_16]: https://owasp.org/Top10/2025/A05_2025-Injection/

[^1_17]: https://blog.intelligencex.org/owasp-a05-2025-injection-vulnerability-guide

[^1_18]: https://owasp.org/Top10/2025/A06_2025-Insecure_Design/

[^1_19]: https://owasp.org/Top10/de/2025/A06_2025-Insecure_Design/

[^1_20]: https://blog.intelligencex.org/owasp-a06-2025-insecure-design-complete-guide

[^1_21]: https://www.indusface.com/learning/owasp-top-10-insecure-design/

[^1_22]: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/

[^1_23]: https://blog.intelligencex.org/owasp-a07-2025-authentication-failures-comprehensive-guide

[^1_24]: https://owasp.org/Top10/es/2025/A08_2025-Software_or_Data_Integrity_Failures/

[^1_25]: https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/

[^1_26]: https://www.invicti.com/blog/web-security/software-and-data-integrity-failures-an-owasp-top-10-risk

[^1_27]: https://blog.securelayer7.net/a08-software-data-integrity/

[^1_28]: https://owasp.org/Top10/de/2025/A09_2025-Logging_and_Alerting_Failures/

[^1_29]: https://owasp.org/Top10/fr/2025/A09_2025-Logging_and_Alerting_Failures/

[^1_30]: https://blog.securelayer7.net/a09-security-logging-and-monitoring/

[^1_31]: https://owasp.org/Top10/ja/2025/A10_2025-Mishandling_of_Exceptional_Conditions/

[^1_32]: https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/

[^1_33]: https://www.linkedin.com/pulse/owasp-a102025-mishandling-exceptional-conditions-cjl9c

[^1_34]: https://jtika.if.unram.ac.id/index.php/JTIKA/article/view/456

[^1_35]: https://ieeexplore.ieee.org/document/11252191/

[^1_36]: https://ieeexplore.ieee.org/document/11022644/

[^1_37]: https://ieeexplore.ieee.org/document/11023451/

[^1_38]: https://www.mdpi.com/1424-8220/25/9/2913

[^1_39]: https://dl.acm.org/doi/10.1145/3719027.3744825

[^1_40]: https://ojs.bonviewpress.com/index.php/AAES/article/view/4016

[^1_41]: https://arxiv.org/abs/2512.19997

[^1_42]: https://itscience.org/jurnal/index.php/digitech/article/view/6948

[^1_43]: https://www.mdpi.com/2079-9292/14/18/3742

[^1_44]: https://downloads.hindawi.com/journals/wcmc/2022/1657627.pdf

[^1_45]: https://dl.acm.org/doi/pdf/10.1145/3658644.3690227

[^1_46]: https://ijece.iaescore.com/index.php/IJECE/article/download/33835/17135

[^1_47]: https://arxiv.org/pdf/2304.10600.pdf

[^1_48]: https://arxiv.org/pdf/2201.10833.pdf

[^1_49]: https://arxiv.org/pdf/2212.06606.pdf

[^1_50]: https://arxiv.org/pdf/2310.14137.pdf

[^1_51]: http://arxiv.org/pdf/2308.04964.pdf

[^1_52]: https://www.linkedin.com/pulse/owasp-a012025-broken-access-control-cyberhorizon-defentech-mvbdc

[^1_53]: https://www.devfiddle.com/2025/09/owasp-top-10--broken-access-control.html

[^1_54]: https://blog.intelligencex.org/broken-access-control-owasp-a01-2025-complete-guide

[^1_55]: https://www.authgear.com/post/owasp-2025-software-supply-chain-failures

[^1_56]: https://cwe.mitre.org/data/definitions/1437.html

[^1_57]: https://ejournal.itn.ac.id/index.php/jati/article/view/10599

[^1_58]: https://arxiv.org/ftp/arxiv/papers/2312/2312.00499.pdf

[^1_59]: https://arxiv.org/pdf/2412.19310.pdf

[^1_60]: https://arxiv.org/html/2412.07300v1

[^1_61]: https://arxiv.org/pdf/2209.11103.pdf

[^1_62]: https://arxiv.org/pdf/2111.03859.pdf

[^1_63]: https://arxiv.org/pdf/2307.06520.pdf

[^1_64]: http://arxiv.org/pdf/2308.14450.pdf

[^1_65]: https://dl.acm.org/doi/pdf/10.1145/3576915.3616629

[^1_66]: https://blog.securelayer7.net/a02-cryptographic-failures/

[^1_67]: https://www.linkedin.com/pulse/owasp-a062025-insecure-design-cyberhorizon-defentech-991uc

[^1_68]: https://www.youtube.com/watch?v=w5EcyES-Jxc

[^1_69]: https://blog.intelligencex.org/owasp-a04-2025-cryptographic-failures-guide

[^1_70]: https://owasp.org/Top10/ja/2025/A05_2025-Injection/

[^1_71]: https://ieeexplore.ieee.org/document/11283324/

[^1_72]: https://ieeexplore.ieee.org/document/11157553/

[^1_73]: https://arxiv.org/ftp/arxiv/papers/2101/2101.12604.pdf

[^1_74]: https://arxiv.org/pdf/2309.00744.pdf

[^1_75]: http://arxiv.org/pdf/2407.20459.pdf

[^1_76]: https://arxiv.org/pdf/2409.00546.pdf

[^1_77]: https://dl.acm.org/doi/pdf/10.1145/3576915.3623072

[^1_78]: https://arxiv.org/pdf/2205.10174.pdf

[^1_79]: https://www.indusface.com/blog/owasp-a09-logging-monitoring-failures/

[^1_80]: https://www.youtube.com/watch?v=P0UOaj5n4y8

[^1_81]: https://www.linkedin.com/pulse/owasp-a072025-authentication-failures-cyberhorizon-defentech-pl1ac

[^1_82]: https://www.youtube.com/watch?v=IDKhNPlHMOY

[^1_83]: https://www.linkedin.com/pulse/understanding-a082021-software-data-integrity-failures-ftlgc

[^1_84]: https://ijsrem.com/download/mishandling-of-exceptional-conditions-vulnerability-a-detailed-study/

[^1_85]: http://arxiv.org/pdf/2301.09258.pdf

[^1_86]: http://arxiv.org/pdf/2303.12340.pdf

[^1_87]: https://dl.acm.org/doi/pdf/10.1145/3611643.3613889

[^1_88]: https://arxiv.org/pdf/1803.05529.pdf

[^1_89]: https://www.mdpi.com/2076-3417/13/22/12180/pdf?version=1699532302

[^1_90]: https://www.mdpi.com/2073-431X/12/11/235/pdf?version=1700031764

[^1_91]: https://arxiv.org/pdf/2311.10450.pdf

[^1_92]: https://www.securecodewarrior.com/article/new-risk-category-on-the-owasp-top-ten-expecting-the-unexpected

[^1_93]: https://www.authgear.com/post/owasp-2025-mishandling-of-exceptional-conditions

[^1_94]: https://www.linkedin.com/posts/nithya-govindaraj-80b86077_introduction-activity-7393664807989735424-sgOb

[^1_95]: https://www.reflectiz.com/blog/owasp-top-ten-2025/

[^1_96]: https://www.cryptika.com/owasp-top-10-2025-revised-version-released-with-two-new-categories/

[^1_97]: https://owasp.org/Top10/pt-BR/2025/A10_2025-Mishandling_of_Exceptional_Conditions/

[^1_98]: https://www.siteguarding.com/security-blog/owasp-top-10-2025-whats-new-whats-critical-and-how-you-should-prepare/

[^1_99]: https://www.linkedin.com/posts/harsh-tandel-939785193_owasp-top10-cybersecurity-activity-7392469046581096449-JRJk

[^1_100]: https://cwe.mitre.org/data/definitions/1445.html

[^1_101]: https://www.reddit.com/r/cybersecurity/comments/1oskatm/owasp_2025_top_10_for_web_released_what_are_your/

[^1_102]: https://www.linkedin.com/posts/cybersecurity-news_cybersecuirtynews-activity-7393724141427736576-UjP9


---

# Django와 MariaDB를 이용해서 할거야. 그 스택에서 자주 나오는 취약 코드 패턴과 구체적인 방어 코드 템플릿을 따로 정리해줘.

완벽합니다! 이제 Django + MariaDB 스택에서 OWASP Top 10:2025 각 항목별로 자주 나오는 취약 코드 패턴과 방어 코드를 체계적으로 정리해드리겠습니다.

***

# Django + MariaDB 스택의 OWASP Top 10:2025 취약점 패턴 \& 방어 코드

## A01: Broken Access Control (취약한 접근 제어)

### 취약 패턴 1: IDOR (직접 객체 참조)

```python
# views.py - 취약한 코드
from django.shortcuts import render
from django.http import HttpResponse
from .models import Order

def view_order(request):
    order_id = request.GET.get('order_id')
    # 로그인한 사용자와 관계 없이 order_id로만 조회
    order = Order.objects.filter(id=order_id).first()
    if not order:
        return HttpResponse("Order not found", status=404)
    return render(request, 'order_detail.html', {'order': order})
```

**문제**: 공격자가 `?order_id=999`로 다른 사용자의 주문을 조회 가능.

### 방어 코드 1: 소유자 검증 필수

```python
# views.py - 안전한 코드
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from .models import Order

@login_required
def view_order(request, order_id):
    # 데이터베이스에서 현재 사용자와 order 소유자를 함께 검증
    order = get_object_or_404(
        Order,
        id=order_id,
        user=request.user  # 소유자 확인 필수
    )
    return render(request, 'order_detail.html', {'order': order})
```


### 취약 패턴 2: 클라이언트 신호만 믿고 서버 권한 체크 없음

```python
# views.py - 취약한 코드
from django.views import View
from .models import AdminLog

class DeleteUserView(View):
    def post(self, request):
        user_id = request.POST.get('user_id')
        
        # 클라이언트에서 보낸 role만 믿음
        if request.POST.get('user_role') == 'admin':
            # 실제 권한 검사 없음
            AdminLog.objects.filter(id=user_id).delete()
            return HttpResponse("Deleted")
        return HttpResponseForbidden()
```


### 방어 코드 2: 서버에서 항상 권한 검증

```python
# views.py - 안전한 코드
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views import View
from django.http import HttpResponseForbidden
from .models import AdminLog

def is_admin(user):
    """중앙 집중식 권한 검사 함수"""
    return user.is_authenticated and user.is_staff

@login_required
@user_passes_test(is_admin)
def delete_admin_log(request, log_id):
    # 서버에서 현재 사용자의 실제 권한 검증
    if not request.user.is_staff:
        return HttpResponseForbidden("Access Denied")
    
    # DB에서 권한 검사
    log = get_object_or_404(AdminLog, id=log_id)
    log.delete()
    return HttpResponse("Deleted successfully")
```


### 취약 패턴 3: 역할별 API 엔드포인트 보호 부재

```python
# urls.py - 취약한 구성
from django.urls import path
from . import views

urlpatterns = [
    path('api/admin/users/delete/', views.delete_user),  # 권한 검사 없음
    path('api/user/profile/', views.get_profile),
]
```


### 방어 코드 3: 데코레이터 기반 권한 통제

```python
# decorators.py - 중앙 집중식 권한 데코레이터
from functools import wraps
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required

def require_role(*roles):
    """역할 기반 접근 제어 데코레이터"""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            # 데이터베이스에서 사용자의 실제 역할 확인
            user_role = request.user.groups.values_list('name', flat=True)
            if not any(role in user_role for role in roles):
                return HttpResponseForbidden("You don't have permission")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# views.py
@require_role('admin', 'moderator')
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return HttpResponse("User deleted")
```


### 취약 패턴 4: 객체 소유 검증 없이 수정

```python
# views.py - 취약한 코드
from .models import UserProfile

def update_profile(request):
    profile_id = request.POST.get('profile_id')
    profile = UserProfile.objects.get(id=profile_id)  # 소유자 검증 없음
    profile.bio = request.POST.get('bio')
    profile.save()
    return HttpResponse("Updated")
```


### 방어 코드 4: 소유자 검증 추가

```python
# views.py - 안전한 코드
from django.core.exceptions import PermissionDenied

@login_required
def update_profile(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    
    # 현재 사용자가 이 프로필의 소유자인지 검증
    if profile.user != request.user:
        raise PermissionDenied("You can only edit your own profile")
    
    profile.bio = request.POST.get('bio')
    profile.full_clean()  # 데이터 유효성 검사
    profile.save()
    return HttpResponse("Profile updated successfully")
```


***

## A02: Security Misconfiguration (보안 설정 오류)

### 취약 패턴 1: 프로덕션에서 DEBUG=True

```python
# settings.py - 취약한 코드
DEBUG = True  # 프로덕션에서도 True
SECRET_KEY = "hardcoded-secret-key-in-code"
ALLOWED_HOSTS = ['*']  # 모든 호스트 허용

# 데이터베이스 비밀번호도 코드에 직접 입력
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'mydb',
        'USER': 'root',
        'PASSWORD': 'password123',  # 노출됨
        'HOST': 'localhost',
    }
}
```

**문제**:

- DEBUG=True일 때 스택 트레이스, 환경변수, 쿼리 로그 등이 사용자에게 노출
- SECRET_KEY 노출 시 세션 토큰 위조 가능


### 방어 코드 1: 환경 변수 사용 \& 환경별 분리

```python
# settings.py - 안전한 코드
import os
from pathlib import Path

# 환경 변수에서 설정 읽기
DEBUG = os.getenv('DEBUG', 'False') == 'True'
SECRET_KEY = os.getenv('SECRET_KEY')  # .env 파일에서 읽음

if not SECRET_KEY:
    raise ValueError("SECRET_KEY 환경 변수가 설정되지 않았습니다.")

# 호스트 화이트리스트
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

# 데이터베이스 설정
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.getenv('DB_NAME', 'mydb'),
        'USER': os.getenv('DB_USER', 'root'),
        'PASSWORD': os.getenv('DB_PASSWORD'),  # .env에서 읽음
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '3306'),
    }
}

# 프로덕션 환경 설정
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
```


### .env 파일 예시

```bash
# .env (절대 git에 커밋하면 안 됨, .gitignore에 추가)
DEBUG=False
SECRET_KEY=your-super-secret-key-generated-by-django
DB_NAME=mydb
DB_USER=django_user
DB_PASSWORD=strong-password-here
DB_HOST=db.example.com
DB_PORT=3306
ALLOWED_HOSTS=example.com,www.example.com
```


### requirements.txt에서 python-dotenv 설치

```bash
pip install python-dotenv
```


### manage.py 또는 wsgi.py에서 로드

```python
# wsgi.py 또는 manage.py 상단
import os
from pathlib import Path
from dotenv import load_dotenv

# .env 파일 로드
env_file = Path(__file__).resolve().parent.parent / '.env'
load_dotenv(str(env_file))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
```


### 취약 패턴 2: 기본 계정 미제거 \& 보안 헤더 미설정

```python
# settings.py - 취약한 코드
# Django 관리자 기본 경로 그대로 사용
ADMIN_URL_PATH = '/admin/'

# 보안 헤더 없음
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # 나머지 미들웨어만 있음
]

# CSRF 설정 미흡
CSRF_COOKIE_SECURE = False  # HTTP에서도 전송 가능
```


### 방어 코드 2: 관리자 URL 변경 \& 보안 헤더 추가

```python
# settings.py - 안전한 코드
# 관리자 URL 변경
ADMIN_URL_PATH = 'hidden-admin-panel-' + os.getenv('SECRET_ADMIN_PATH', 'default123')

# urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Django 관리자를 기본 /admin/ 대신 숨겨진 경로로
    path(os.getenv('ADMIN_URL', 'admin-panel/'), admin.site.urls),
]

# 보안 헤더 설정
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# 추가 보안 설정
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_SECURITY_POLICY = {
    "default-src": ("'self'",),
    "script-src": ("'self'", "cdn.example.com"),
}

# CSRF & 세션 쿠키 보안
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 3600  # 1시간

# 불필요한 정보 노출 방지
SECURE_SERVER_VARIABLE_NAME = 'HTTP_X_FORWARDED_FOR'
```


***

## A03: Software Supply Chain Failures (소프트웨어 공급망 실패)

### 취약 패턴 1: 버전 고정 없이 최신 의존성 설치

```bash
# requirements.txt - 취약한 코드
django
djangorestframework
celery
psycopg2
pillow
```

**문제**: `pip install -r requirements.txt`할 때마다 최신 버전을 받아서 예상 못한 버그나 악성 패키지 위험.

### 방어 코드 1: 정확한 버전 고정

```bash
# requirements.txt - 안전한 코드
django==5.2.1
djangorestframework==3.14.0
celery==5.4.0
psycopg2-binary==2.9.10
pillow==10.1.0
# 개발용 의존성
pytest==7.4.3
pytest-django==4.7.0
black==24.1.1
```


### 취약 패턴 2: CI/CD 파이프라인에 권한 통제 없음

```yaml
# .github/workflows/deploy.yml - 취약한 구성
name: Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy
        run: |
          pip install -r requirements.txt
          python manage.py migrate
          docker push myregistry/myapp:latest  # 누구나 푸시 가능
```


### 방어 코드 2: CI/CD 보안 강화

```yaml
# .github/workflows/deploy.yml - 안전한 코드
name: Deploy
on:
  push:
    branches:
      - main  # main 브랜치만 배포

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      
      - name: Run security checks
        run: |
          pip install bandit safety
          bandit -r . -ll  # 보안 취약점 스캔
          safety check  # 의존성 취약점 스캔
      
      - name: Run tests
        run: |
          pytest
  
  deploy:
    needs: test  # test 성공 후에만 배포
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'  # main 브랜치만
    steps:
      - uses: actions/checkout@v3
      
      - name: Login to registry
        uses: docker/login-action@v2
        with:
          registry: ${{ secrets.REGISTRY }}
          username: ${{ secrets.REGISTRY_USER }}
          password: ${{ secrets.REGISTRY_PASSWORD }}
      
      - name: Build and push Docker image
        run: |
          docker build -t ${{ secrets.REGISTRY }}/myapp:${{ github.sha }} .
          docker push ${{ secrets.REGISTRY }}/myapp:${{ github.sha }}
```


### 취약 패턴 3: 의존성 버전 정보 없음 (무결성 검증 불가)

```bash
# requirements.txt - 취약한 코드
django
djangorestframework==3.14.0  # 일부만 고정
```


### 방어 코드 3: pip-audit 사용해 알려진 취약점 검사

```bash
# requirements.txt - 안전한 코드 (with hashes)
django==5.2.1 \
    --hash=sha256:abc123def456...
djangorestframework==3.14.0 \
    --hash=sha256:def456ghi789...
```

또는 requirements-lock.txt 생성:

```bash
# 정확한 버전과 해시로 lock 파일 생성
pip freeze > requirements-lock.txt

# lock 파일로 설치 (정확한 버전 보장)
pip install -r requirements-lock.txt
```


***

## A04: Cryptographic Failures (암호학 실패)

### 취약 패턴 1: 평문 또는 약한 해시로 비밀번호 저장

```python
# models.py - 취약한 코드
from django.db import models
import hashlib

class User(models.Model):
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=255)
    
    def set_password(self, raw_password):
        # 평문 저장
        self.password = raw_password
    
    # 또는 약한 해시 사용
    def set_password_weak(self, raw_password):
        self.password = hashlib.md5(raw_password.encode()).hexdigest()
```


### 방어 코드 1: Django의 내장 해시 함수 사용

```python
# models.py - 안전한 코드
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password

# 방법 1: Django의 AbstractUser 상속 (권장)
class CustomUser(AbstractUser):
    """Django 기본 User를 확장"""
    email_verified = models.BooleanField(default=False)
    
    def set_password(self, raw_password):
        # Django의 make_password 자동 호출됨
        super().set_password(raw_password)

# 방법 2: 커스텀 모델에서 명시적으로 해싱
class UserProfile(models.Model):
    username = models.CharField(max_length=100)
    password_hash = models.CharField(max_length=255)
    
    def set_password(self, raw_password):
        # bcrypt/Argon2 사용 (Django 기본: PBKDF2)
        self.password_hash = make_password(raw_password)
    
    def check_password(self, raw_password):
        from django.contrib.auth.hashers import check_password
        return check_password(raw_password, self.password_hash)

# settings.py에서 해시 알고리즘 설정
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',  # 가장 강함
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',  # 기본
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]
```


### 취약 패턴 2: 하드코딩된 암호 키

```python
# settings.py - 취약한 코드
SECRET_KEY = "django-insecure-xyz123abc"  # 코드에 박힘
ENCRYPTION_KEY = "hardcoded-encryption-key"
```


### 방어 코드 2: 환경 변수와 KMS 사용

```python
# settings.py - 안전한 코드
import os
from cryptography.fernet import Fernet

# 환경변수에서 키 읽기
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("DJANGO_SECRET_KEY 환경변수가 설정되지 않았습니다")

# 암호화 키 (프로덕션에서는 AWS KMS 등에서 받아오기)
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if ENCRYPTION_KEY:
    ENCRYPTION_CIPHER = Fernet(ENCRYPTION_KEY.encode())

# models.py
from django.db import models
from cryptography.fernet import Fernet

class SensitiveData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_field = models.TextField()  # 민감한 정보
    
    def set_encrypted_field(self, plaintext):
        """민감한 데이터 암호화해서 저장"""
        cipher = Fernet(os.getenv('ENCRYPTION_KEY').encode())
        self.encrypted_field = cipher.encrypt(plaintext.encode()).decode()
    
    def get_encrypted_field(self):
        """암호화된 데이터 복호화"""
        cipher = Fernet(os.getenv('ENCRYPTION_KEY').encode())
        return cipher.decrypt(self.encrypted_field.encode()).decode()
```


### 취약 패턴 3: HTTPS 미사용 (채널 보안 없음)

```python
# settings.py - 취약한 코드
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False  # HTTP에서도 전송
CSRF_COOKIE_SECURE = False
```


### 방어 코드 3: HTTPS 강제 \& 쿠키 보안

```python
# settings.py - 안전한 코드 (프로덕션)
if not DEBUG:
    # HTTPS 강제
    SECURE_SSL_REDIRECT = True
    
    # 세션/CSRF 쿠키만 HTTPS로 전송
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    
    # HttpOnly 플래그 (JavaScript에서 접근 불가)
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True
    
    # HSTS (HTTP Strict Transport Security)
    SECURE_HSTS_SECONDS = 31536000  # 1년
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True  # HSTS 프리로드 리스트에 포함
```


### Nginx 설정

```nginx
# nginx 설정
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    
    # TLS 1.2 이상만 허용
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # HTTP에서 HTTPS로 리다이렉트
    error_page 497 =301 https://$host$request_uri;
    
    location / {
        proxy_pass http://django:8000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTP를 HTTPS로 리다이렉트
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```


***

## A05: Injection (인젝션)

### 취약 패턴 1: SQL Injection - raw 쿼리에서 문자열 결합

```python
# views.py - 취약한 코드
from django.db import connection
from .models import User

def search_user(request):
    search_term = request.GET.get('q', '')
    
    # 직접 문자열 연결 -> SQL Injection 위험
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor = connection.cursor()
    cursor.execute(query)  # ' UNION SELECT...-- 등으로 우회 가능
    results = cursor.fetchall()
    return render(request, 'results.html', {'results': results})
```


### 방어 코드 1-1: Django ORM 사용 (권장)

```python
# views.py - 안전한 코드 (ORM)
from .models import User

def search_user(request):
    search_term = request.GET.get('q', '')
    
    # Django ORM 사용 (자동 파라미터화)
    users = User.objects.filter(name__icontains=search_term)
    return render(request, 'results.html', {'users': users})
```


### 방어 코드 1-2: raw() 사용 시 params 필수

```python
# views.py - 안전한 코드 (raw 쿼리)
from .models import User

def search_user_raw(request):
    search_term = request.GET.get('q', '')
    
    # raw()에서 params 파라미터 사용 (placeholder %s)
    users = User.objects.raw(
        "SELECT * FROM users WHERE name LIKE %s",
        [f'%{search_term}%']
    )
    return render(request, 'results.html', {'users': users})
```


### 취약 패턴 2: 커스텀 SQL 직접 실행

```python
# views.py - 취약한 코드
from django.db import connection

def get_user_dangerous(user_id):
    # 직접 쿼리 문자열 생성 -> SQLi 위험
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchone()
```


### 방어 코드 2: cursor.execute()에서 params 사용

```python
# views.py - 안전한 코드
from django.db import connection

def get_user_safe(user_id):
    # 파라미터 분리 (플레이스홀더 %s)
    cursor = connection.cursor()
    cursor.execute(
        "SELECT * FROM auth_user WHERE id = %s",
        [user_id]
    )
    return cursor.fetchone()
```


### 취약 패턴 3: 동적 필드명 필터링

```python
# views.py - 취약한 코드
from .models import Product

def filter_products(request):
    field = request.GET.get('sort_by')  # "name" 또는 "price"
    
    # 필드명이 조작 가능
    # ?sort_by=price; DELETE FROM products;--
    products = Product.objects.all().order_by(field)
    return render(request, 'products.html', {'products': products})
```


### 방어 코드 3: 화이트리스트 검증

```python
# views.py - 안전한 코드
from django.db.models import F
from .models import Product

ALLOWED_SORT_FIELDS = {'name', 'price', 'created_at'}  # 화이트리스트

def filter_products(request):
    sort_by = request.GET.get('sort_by', 'name')
    
    # 화이트리스트에서만 선택
    if sort_by not in ALLOWED_SORT_FIELDS:
        sort_by = 'name'
    
    products = Product.objects.all().order_by(sort_by)
    return render(request, 'products.html', {'products': products})
```


### 취약 패턴 4: 템플릿 엔진 Injection (NoSQL/LDAP과 유사)

```python
# views.py - 취약한 코드
from django.db.models import Q
from django.template import Template, Context

def search_with_template(request):
    search_term = request.GET.get('q')
    
    # 사용자 입력을 템플릿으로 사용 -> SSTI 가능
    template_str = f"User: {search_term}"
    t = Template(template_str)
    result = t.render(Context({}))
    
    return HttpResponse(result)
```


### 방어 코드 4: 템플릿은 고정, 데이터는 변수로

```python
# views.py - 안전한 코드
from django.template.loader import render_to_string
from django.template import Context

def search_with_template(request):
    search_term = request.GET.get('q', '')
    
    # 템플릿은 파일에서 로드 (고정)
    # 사용자 입력은 context 변수로 전달
    context = {'search_term': search_term}
    result = render_to_string('search_result.html', context)
    
    return HttpResponse(result)

# search_result.html
# <h1>Search Results for {{ search_term }}</h1>
# Django 템플릿 엔진이 자동으로 이스케이프함
```


***

## A06: Insecure Design (안전하지 않은 설계)

### 취약 패턴 1: 비즈니스 로직 검증 부재 (환불 무제한)

```python
# models.py & views.py - 취약한 코드
from django.db import models

class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    refunded_amount = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, default='pending')

# views.py
def refund_order(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    refund_amount = request.POST.get('amount')
    
    # 환불 한도 체크 없음
    order.refunded_amount += Decimal(refund_amount)
    order.save()  # 원금보다 많이 환불 가능
    
    return HttpResponse("Refunded")
```


### 방어 코드 1: 비즈니스 로직 검증 추가

```python
# models.py
from django.db import models
from django.core.exceptions import ValidationError
from decimal import Decimal

class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    refunded_amount = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, default='pending')
    
    def refund(self, amount):
        """환불 비즈니스 로직"""
        if self.status not in ['completed', 'processing']:
            raise ValidationError("이미 환불된 주문입니다")
        
        # 환불 한도 검증: 원금을 초과할 수 없음
        if self.refunded_amount + amount > self.total_amount:
            raise ValidationError(
                f"환불 금액이 초과되었습니다. "
                f"최대 환불 가능: {self.total_amount - self.refunded_amount}"
            )
        
        # 부분 환불 기록
        refund_record = Refund.objects.create(
            order=self,
            amount=amount,
            created_at=now()
        )
        
        self.refunded_amount += amount
        if self.refunded_amount == self.total_amount:
            self.status = 'fully_refunded'
        else:
            self.status = 'partially_refunded'
        
        self.save()
        return refund_record

# views.py
@login_required
def refund_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    amount = Decimal(request.POST.get('amount', '0'))
    
    try:
        # 비즈니스 로직 검증 호출
        order.refund(amount)
        return render(request, 'refund_success.html', {'order': order})
    except ValidationError as e:
        return render(request, 'refund_error.html', {'error': str(e)})
```


### 취약 패턴 2: 레이스 컨디션 (동시성 문제)

```python
# views.py - 취약한 코드
from .models import Coupon

def apply_coupon(request, coupon_code):
    coupon = Coupon.objects.get(code=coupon_code)
    
    # 동시에 여러 요청이 들어오면 count 중복 증가
    if coupon.usage_count < coupon.max_usage:
        coupon.usage_count += 1  # 원자적이지 않음
        coupon.save()
        return HttpResponse("Coupon applied")
```


### 방어 코드 2: 원자적 연산 사용

```python
# models.py - 안전한 코드
from django.db import models
from django.db.models import F

class Coupon(models.Model):
    code = models.CharField(max_length=50, unique=True)
    max_usage = models.IntegerField()
    usage_count = models.IntegerField(default=0)

# views.py
from django.db import transaction
from django.db.models import F

@transaction.atomic
def apply_coupon(request, coupon_code):
    # SELECT FOR UPDATE로 잠금 획득
    coupon = Coupon.objects.select_for_update().get(code=coupon_code)
    
    if coupon.usage_count < coupon.max_usage:
        # F()를 사용한 원자적 업데이트
        Coupon.objects.filter(id=coupon.id).update(
            usage_count=F('usage_count') + 1
        )
        return HttpResponse("Coupon applied successfully")
    else:
        return HttpResponse("Coupon usage limit exceeded", status=400)
```


### 취약 패턴 3: 워크플로우 순서 우회

```python
# models.py & views.py - 취약한 코드
class PaymentWorkflow(models.Model):
    STEP_CHOICES = [
        ('1_checkout', '결제 정보 입력'),
        ('2_payment', '결제 승인'),
        ('3_confirmation', '확인'),
    ]
    order = models.OneToOneField(Order, on_delete=models.CASCADE)
    current_step = models.CharField(max_length=20, choices=STEP_CHOICES)

# views.py
def skip_to_confirmation(request, order_id):
    workflow = PaymentWorkflow.objects.get(order__id=order_id)
    
    # 순서 검증 없이 직접 상태 변경 가능
    workflow.current_step = '3_confirmation'
    workflow.save()  # 결제 스킵 가능!
    
    return HttpResponse("Confirmed")
```


### 방어 코드 3: 상태 전환 검증

```python
# models.py - 안전한 코드
from django.db import models
from django.core.exceptions import ValidationError

class PaymentWorkflow(models.Model):
    STEP_CHOICES = [
        ('1_checkout', '결제 정보 입력'),
        ('2_payment', '결제 승인'),
        ('3_confirmation', '확인'),
    ]
    
    ALLOWED_TRANSITIONS = {
        '1_checkout': ['2_payment'],
        '2_payment': ['3_confirmation'],
        '3_confirmation': [],
    }
    
    order = models.OneToOneField(Order, on_delete=models.CASCADE)
    current_step = models.CharField(max_length=20, choices=STEP_CHOICES, default='1_checkout')
    
    def transition_to(self, next_step):
        """상태 전환 검증"""
        allowed_steps = self.ALLOWED_TRANSITIONS.get(self.current_step, [])
        
        if next_step not in allowed_steps:
            raise ValidationError(
                f"'{self.current_step}'에서 '{next_step}'로 전환할 수 없습니다. "
                f"허용된 다음 단계: {allowed_steps}"
            )
        
        self.current_step = next_step
        self.save()

# views.py
def process_payment(request, order_id):
    workflow = PaymentWorkflow.objects.get(order__id=order_id)
    
    try:
        # 정해진 순서대로만 전환 가능
        workflow.transition_to('2_payment')
        # ... 결제 처리 로직 ...
        workflow.transition_to('3_confirmation')
        return HttpResponse("Payment successful")
    except ValidationError as e:
        return HttpResponse(str(e), status=400)
```


***

## A07: Authentication Failures (인증 실패)

### 취약 패턴 1: 약한 비밀번호 정책

```python
# settings.py & views.py - 취약한 코드
# 비밀번호 길이 제한 없음
AUTH_PASSWORD_VALIDATORS = []

# views.py
def register(request):
    password = request.POST.get('password')
    if len(password) < 3:  # 너무 약함
        return HttpResponse("Password too short")
```


### 방어 코드 1: 강력한 비밀번호 정책

```python
# settings.py - 안전한 코드
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # 최소 12자
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    # 커스텀 검증기
    {
        'NAME': 'accounts.validators.ComplexPasswordValidator',
    },
]

# accounts/validators.py - 커스텀 검증기
import re
from django.core.exceptions import ValidationError

class ComplexPasswordValidator:
    def validate(self, password, user=None):
        """대문자, 소문자, 숫자, 특수문자 포함 검증"""
        if not re.search(r'[A-Z]', password):
            raise ValidationError("비밀번호에 대문자가 포함되어야 합니다")
        if not re.search(r'[a-z]', password):
            raise ValidationError("비밀번호에 소문자가 포함되어야 합니다")
        if not re.search(r'\d', password):
            raise ValidationError("비밀번호에 숫자가 포함되어야 합니다")
        if not re.search(r'[!@#$%^&*]', password):
            raise ValidationError("비밀번호에 특수문자(!@#$%^&*)가 포함되어야 합니다")
    
    def get_help_text(self):
        return "비밀번호는 12자 이상, 대소문자, 숫자, 특수문자를 포함해야 합니다"

# forms.py
from django import forms
from django.contrib.auth.models import User

class RegistrationForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)
    
    class Meta:
        model = User
        fields = ['username', 'email']
    
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        if password1 != password2:
            raise forms.ValidationError("비밀번호가 일치하지 않습니다")
        
        # Django의 비밀번호 검증기 사용
        from django.contrib.auth.password_validation import validate_password
        try:
            validate_password(password1)
        except ValidationError as e:
            self.add_error('password1', e)
        
        return cleaned_data
```


### 취약 패턴 2: 로그인 시도 제한 없음 (무작위 대입 공격)

```python
# views.py - 취약한 코드
from django.contrib.auth import authenticate, login

def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    user = authenticate(username=username, password=password)
    if user:
        login(request, user)
    else:
        return HttpResponse("Invalid credentials")  # 제한 없음
```


### 방어 코드 2: Rate Limiting \& 계정 잠금

```python
# pip install django-axes
# settings.py - 안전한 코드
INSTALLED_APPS = [
    ...
    'axes',
]

MIDDLEWARE = [
    ...
    'axes.middleware.AxesMiddleware',  # 반드시 마지막
]

AXES_FAILURE_LIMIT = 5  # 5회 실패 후 잠금
AXES_COOLOFF_DURATION = timedelta(minutes=15)  # 15분 잠금
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

# models.py
from django.db import models
from django.utils import timezone

class LoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    ip_address = models.GenericIPAddressField()
    attempted_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)

# views.py
from django.utils.decorators import method_decorator
from axes.decorators import sensitive_post_parameters, axes_dispatch_decorator
from django.http import HttpResponse

@sensitive_post_parameters('password')
@axes_dispatch_decorator
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(username=username, password=password)
        
        if user:
            # axes가 자동으로 시도 횟수 초기화
            login(request, user)
            return redirect('dashboard')
        else:
            # axes가 자동으로 시도 횟수 증가
            return render(request, 'login.html', {
                'error': 'Invalid credentials. 5회 실패 시 계정이 잠깁니다.'
            })
```


### 취약 패턴 3: 세션 토큰을 URL에 노출

```python
# views.py - 취약한 코드
from django.http import HttpResponse

def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    if authenticate(username=username, password=password):
        # 세션 ID를 URL에 담아서 리다이렉트 -> 로그에 노출, 공유 시 세션 탈취
        return redirect(f'/dashboard/?sid={request.session.session_key}')
```


### 방어 코드 3: 쿠키 기반 세션 \& HttpOnly 플래그

```python
# settings.py - 안전한 코드
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 3600  # 1시간
SESSION_COOKIE_SECURE = True  # HTTPS만
SESSION_COOKIE_HTTPONLY = True  # JavaScript 접근 불가
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF 방지

# views.py
from django.contrib.auth import authenticate, login

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(username=username, password=password)
        
        if user:
            login(request, user)  # 세션은 자동으로 쿠키에 저장
            return redirect('dashboard')  # URL에는 세션 정보 없음
```


### 취약 패턴 4: MFA 없음 \& 비밀번호 복구 취약

```python
# views.py - 취약한 코드
def forgot_password(request):
    email = request.POST.get('email')
    user = User.objects.get(email=email)
    
    # 보안 질문 (답변이 쉽게 알려질 수 있음)
    if request.POST.get('mother_name') == user.mother_name:
        # 비밀번호를 그냥 리셋 -> 공격자도 가능
        new_password = 'temp123'
        user.set_password(new_password)
        user.save()
        return HttpResponse(f"Password reset to: {new_password}")
```


### 방어 코드 4: MFA \& 안전한 비밀번호 복구

```bash
# MFA 라이브러리 설치
pip install django-otp
pip install qrcode pillow
```

```python
# settings.py - 안전한 코드
INSTALLED_APPS = [
    ...
    'django_otp',
    'django_otp.plugins.otp_totp',
]

MIDDLEWARE = [
    ...
    'django_otp.middleware.OTPMiddleware',
]

# models.py
from django.db import models
from django.utils import timezone

class PasswordResetToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def is_valid(self):
        return timezone.now() < self.expires_at

# views.py
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            
            # 토큰 생성 (유효시간 1시간)
            token = default_token_generator.make_token(user)
            reset_token = PasswordResetToken.objects.create(
                user=user,
                token=token,
                expires_at=timezone.now() + timedelta(hours=1)
            )
            
            # 이메일로 리셋 링크 전송
            reset_link = f"https://example.com/reset-password/{token}/"
            send_mail(
                '비밀번호 초기화',
                f'다음 링크를 클릭해 비밀번호를 초기화하세요 (1시간 유효):\n{reset_link}',
                'noreply@example.com',
                [email],
            )
            return render(request, 'password_reset_email_sent.html')
        except User.DoesNotExist:
            # 존재하지 않는 이메일도 같은 메시지 반환 (사용자 열거 공격 방지)
            return render(request, 'password_reset_email_sent.html')

def reset_password(request, token):
    try:
        reset_token = PasswordResetToken.objects.get(token=token)
        
        if not reset_token.is_valid():
            return render(request, 'password_reset_expired.html')
        
        if request.method == 'POST':
            new_password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            
            if new_password != confirm_password:
                return render(request, 'password_reset_form.html', {
                    'error': '비밀번호가 일치하지 않습니다'
                })
            
            # 비밀번호 정책 검증
            from django.contrib.auth.password_validation import validate_password
            try:
                validate_password(new_password)
            except ValidationError as e:
                return render(request, 'password_reset_form.html', {'error': str(e)})
            
            user = reset_token.user
            user.set_password(new_password)
            user.save()
            reset_token.delete()
            
            return render(request, 'password_reset_success.html')
        
        return render(request, 'password_reset_form.html', {'token': token})
    
    except PasswordResetToken.DoesNotExist:
        return render(request, 'password_reset_invalid.html')

# 2FA (TOTP) 설정
from django.contrib.auth.decorators import login_required
from django_otp.decorators import otp_required
from django_otp.plugins.otp_totp.models import StaticDevice

@login_required
def setup_2fa(request):
    user = request.user
    device, created = StaticDevice.objects.get_or_create(
        user=user,
        name='2FA Device'
    )
    
    if created:
        # 백업 토큰 생성
        from django_otp.plugins.otp_totp.models import TOTPDevice
        totp_device, _ = TOTPDevice.objects.get_or_create(user=user)
        qr_code = totp_device.config_url
        
        return render(request, 'setup_2fa.html', {'qr_code': qr_code})

# 2FA 보호된 뷰
@login_required
@otp_required
def dashboard(request):
    return render(request, 'dashboard.html')
```


***

## A08: Software or Data Integrity Failures (소프트웨어/데이터 무결성 실패)

### 취약 패턴 1: 서명 없이 업데이트 다운로드

```python
# views.py - 취약한 코드
import os
import requests

def download_and_apply_update(request):
    url = "https://updates.example.com/app-update.tar.gz"
    response = requests.get(url)
    
    # 서명/해시 검증 없이 받음
    with open('/opt/app/update.tar.gz', 'wb') as f:
        f.write(response.content)
    
    os.system('tar -xzf /opt/app/update.tar.gz -C /opt/app/')
    os.system('/opt/app/install.sh')  # 악성 스크립트 실행 가능
```


### 방어 코드 1: 서명 및 해시 검증

```python
# views.py - 안전한 코드
import hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def download_and_apply_update(request):
    url = "https://updates.example.com/app-update.tar.gz"
    signature_url = url + ".sig"
    
    # 1. 업데이트 파일 다운로드
    response = requests.get(url)
    update_content = response.content
    
    # 2. 서명 파일 다운로드
    sig_response = requests.get(signature_url)
    signature = sig_response.content
    
    # 3. 공개키로 서명 검증
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    try:
        public_key.verify(
            signature,
            update_content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("✓ 서명 검증 성공")
    except Exception as e:
        raise ValueError(f"서명 검증 실패: {e}")
    
    # 4. 해시 검증 (추가 보안)
    expected_hash = "abc123def456..."  # 안전한 채널에서 미리 받아온 해시
    actual_hash = hashlib.sha256(update_content).hexdigest()
    
    if actual_hash != expected_hash:
        raise ValueError("해시 검증 실패")
    
    # 5. 안전하게 설치
    with open('/opt/app/update.tar.gz', 'wb') as f:
        f.write(update_content)
    
    os.system('tar -xzf /opt/app/update.tar.gz -C /opt/app/')
    os.system('/opt/app/install.sh')
```


### 취약 패턴 2: 신뢰 안 되는 데이터 역직렬화

```python
# views.py - 취약한 코드
import pickle

def deserialize_user_data(request):
    data = request.POST.get('data')
    
    # pickle로 직렬화된 데이터 역직렬화 -> RCE 위험
    user_data = pickle.loads(data)  # 악성 객체 실행 가능
    return render(request, 'user.html', {'data': user_data})
```


### 방어 코드 2: JSON 사용 \& 타입 검증

```python
# views.py - 안전한 코드
import json
from django.core.serializers.json import JSONDecoder

def deserialize_user_data(request):
    data = request.POST.get('data')
    
    # JSON 사용 (pickle 대신)
    try:
        user_data = json.loads(data)
    except json.JSONDecodeError:
        return HttpResponse("Invalid JSON", status=400)
    
    # 예상 필드만 사용
    allowed_fields = {'name', 'email', 'age'}
    cleaned_data = {k: user_data[k] for k in allowed_fields if k in user_data}
    
    return render(request, 'user.html', {'data': cleaned_data})
```


***

## A09: Security Logging \& Alerting Failures (보안 로깅 및 알림 실패)

### 취약 패턴 1: 로그인 실패 기록 없음 \& 민감 정보 로그

```python
# settings.py & views.py - 취약한 코드
LOGGING = {}  # 로깅 설정 없음

# views.py
def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    user = authenticate(username=username, password=password)
    if user:
        login(request, user)
    else:
        # 실패 기록 없음
        print(f"Failed login for {username} with password {password}")  # 민감 정보 노출
        return HttpResponse("Invalid")
```


### 방어 코드 1: 중앙 집중식 로깅 \& 민감 정보 마스킹

```python
# settings.py - 안전한 코드
import logging

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/django/app.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'security_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/django/security.log',
            'maxBytes': 1024 * 1024 * 10,
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'security': {
            'handlers': ['security_file'],
            'level': 'INFO',
        },
        'django.security': {
            'handlers': ['security_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# loggers/security.py - 보안 로거
import logging
import json
from django.utils import timezone

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
    
    def log_login_attempt(self, username, ip, success):
        """로그인 시도 기록 (비밀번호는 로그하지 않음)"""
        event = {
            'timestamp': timezone.now().isoformat(),
            'event_type': 'login_attempt',
            'username': username,
            'ip_address': ip,
            'success': success,
            'method': 'password'
        }
        self.logger.info(json.dumps(event))
    
    def log_unauthorized_access(self, user, resource, ip):
        """권한 없는 접근 기록"""
        event = {
            'timestamp': timezone.now().isoformat(),
            'event_type': 'unauthorized_access',
            'user_id': user.id if user else None,
            'resource': resource,
            'ip_address': ip,
            'severity': 'HIGH'
        }
        self.logger.warning(json.dumps(event))
    
    def log_admin_action(self, admin_user, action, target_object, ip):
        """관리자 액션 기록"""
        event = {
            'timestamp': timezone.now().isoformat(),
            'event_type': 'admin_action',
            'admin_user_id': admin_user.id,
            'action': action,
            'target': str(target_object),
            'ip_address': ip,
        }
        self.logger.info(json.dumps(event))

security_logger = SecurityLogger()

# views.py
from django.contrib.auth import authenticate, login
from loggers.security import security_logger

def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    ip = get_client_ip(request)
    
    user = authenticate(username=username, password=password)
    
    if user:
        login(request, user)
        security_logger.log_login_attempt(username, ip, success=True)
        return redirect('dashboard')
    else:
        security_logger.log_login_attempt(username, ip, success=False)
        return HttpResponse("Invalid credentials")

def get_client_ip(request):
    """클라이언트 IP 추출"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[^2_0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
```


### 취약 패턴 2: 에러 시 상세 정보 사용자에게 노출

```python
# views.py - 취약한 코드
def api_endpoint(request):
    try:
        user = User.objects.get(id=request.GET.get('id'))
        # ... 처리 ...
    except Exception as e:
        # 스택 트레이스를 그대로 반환
        return HttpResponse(str(e), status=500)
```


### 방어 코드 2: 전역 에러 핸들러

```python
# views.py 또는 middleware.py - 안전한 코드
import logging

logger = logging.getLogger('django')

def custom_error_handler(request, exception):
    """전역 에러 핸들러"""
    request_id = request.META.get('X-Request-ID')
    ip = get_client_ip(request)
    
    # 서버 로그에만 상세 정보 기록
    logger.error(
        f"Error occurred",
        exc_info=exception,
        extra={
            'request_id': request_id,
            'ip_address': ip,
            'path': request.path,
            'method': request.method,
        }
    )
    
    # 사용자에게는 일반 메시지만 반환
    return render(request, 'error.html', {
        'message': 'An error occurred. Please try again later.',
        'request_id': request_id,  # 지원팀이 로그 조회할 때 사용
    }, status=500)

# settings.py
import uuid
from django.utils.deprecation import MiddlewareMixin

class RequestIDMiddleware(MiddlewareMixin):
    """요청에 고유 ID 추가 (로깅/추적용)"""
    def process_request(self, request):
        request.request_id = str(uuid.uuid4())
        request.META['X-Request-ID'] = request.request_id
```


***

## A10: Mishandling of Exceptional Conditions (예외 상황 처리 미흡)

### 취약 패턴 1: Fail-Open (권한 검사 실패 시 허용)

```python
# views.py - 취약한 코드
def delete_user(request, user_id):
    try:
        # 권한 체크 시도
        acl_check(request.user, 'delete_user')
    except Exception:
        # 권한 검사 실패해도 계속 진행 (Fail-Open)
        pass
    
    user = User.objects.get(id=user_id)
    user.delete()  # 권한 없는 사용자도 삭제 가능!
    return HttpResponse("Deleted")
```


### 방어 코드 1: Fail-Closed

```python
# views.py - 안전한 코드
from django.core.exceptions import PermissionDenied

def delete_user(request, user_id):
    try:
        # 권한 체크 (실패하면 예외 발생)
        if not request.user.is_staff:
            raise PermissionDenied("Admin access required")
    except PermissionDenied:
        # 권한 검사 실패 -> 처리 중단 (Fail-Closed)
        raise
    
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return HttpResponse("Deleted successfully")
```


### 취약 패턴 2: 리소스 정리 부재 (DoS 위험)

```python
# views.py - 취약한 코드
def upload_file(request):
    file = request.FILES.get('file')
    temp_file = open(f'/tmp/{file.name}', 'wb')
    
    try:
        for chunk in file.chunks():
            temp_file.write(chunk)
    except Exception as e:
        # close() 없이 반환 -> 파일 핸들 누수, 디스크 고갈
        return HttpResponse(f"Error: {e}")
    
    return HttpResponse("Upload successful")
```


### 방어 코드 2: Context Manager 사용

```python
# views.py - 안전한 코드
import os
from django.core.files.storage import default_storage

def upload_file(request):
    file = request.FILES.get('file')
    
    # 파일 크기 검증
    MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB
    if file.size > MAX_UPLOAD_SIZE:
        return HttpResponse("File too large", status=413)
    
    # context manager로 자동 정리
    try:
        temp_path = f'/tmp/{file.name}'
        with open(temp_path, 'wb') as temp_file:
            for chunk in file.chunks():
                temp_file.write(chunk)
        
        # 성공 시에만 스토리지에 저장
        with open(temp_path, 'rb') as f:
            default_storage.save(f'uploads/{file.name}', f)
        
        return HttpResponse("Upload successful")
    
    except IOError as e:
        return HttpResponse(f"Upload failed: {str(e)}", status=500)
    
    finally:
        # 임시 파일 정리 (예외 발생 여부와 관계없이 실행)
        if os.path.exists(temp_path):
            os.remove(temp_path)
```


### 취약 패턴 3: 에러 응답이 민감 정보 노출

```python
# views.py - 취약한 코드
def process_payment(request):
    try:
        # DB 연결 실패 시 스택 트레이스 노출
        payment = Payment.objects.get(id=request.GET.get('id'))
        process(payment)
    except Exception as e:
        return HttpResponse(f"Error: {type(e).__name__}: {str(e)}", status=500)
```


### 방어 코드 3: 체계적인 예외 처리

```python
# exceptions.py - 커스텀 예외
class PaymentException(Exception):
    def __init__(self, message, user_message=None, status_code=400):
        self.message = message
        self.user_message = user_message or "An error occurred"
        self.status_code = status_code

# views.py - 안전한 코드
import logging
from django.http import JsonResponse

logger = logging.getLogger('django')

def process_payment(request):
    try:
        payment_id = request.GET.get('id')
        
        if not payment_id:
            raise PaymentException(
                "Missing payment_id parameter",
                "Payment ID is required",
                status_code=400
            )
        
        payment = get_object_or_404(Payment, id=payment_id)
        result = process_payment_transaction(payment)
        
        return JsonResponse({'status': 'success', 'transaction_id': result})
    
    except PaymentException as e:
        # 예상한 에러 -> 사용자 메시지만 반환
        logger.warning(f"Payment error: {e.message}")
        return JsonResponse(
            {'error': e.user_message},
            status=e.status_code
        )
    
    except Exception as e:
        # 예상 못한 에러 -> 상세 정보는 로그에만, 사용자에겐 일반 메시지
        logger.exception(f"Unexpected payment error: {str(e)}")
        return JsonResponse(
            {'error': 'Payment processing failed. Please try again later.'},
            status=500
        )

# middleware.py - 전역 예외 핸들러
from django.utils.deprecation import MiddlewareMixin

class ExceptionHandlingMiddleware(MiddlewareMixin):
    def process_exception(self, request, exception):
        if isinstance(exception, PaymentException):
            return JsonResponse(
                {'error': exception.user_message},
                status=exception.status_code
            )
        
        # 나머지 예외는 Django의 기본 핸들러에 맡김
        return None
```


***

## 추가: CSRF 보호 (모든 POST 요청에서 필수)

### 취약 패턴: CSRF 토큰 없음

```html
<!-- 취약한 HTML -->
<form method="post" action="/delete-account/">
    <input type="text" name="password">
    <button type="submit">Delete Account</button>
</form>
```


### 방어 코드: CSRF 토큰 추가

```html
<!-- 안전한 HTML -->
<form method="post" action="/delete-account/">
    {% csrf_token %}  <!-- 필수 -->
    <input type="password" name="password">
    <button type="submit">Delete Account</button>
</form>
```


### AJAX에서 CSRF 토큰 사용

```javascript
// 토큰 추출
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

const csrftoken = getCookie('csrftoken');

// AJAX 요청
fetch('/api/delete-account/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken,  // 헤더에 토큰 추가
    },
    body: JSON.stringify({ password: '...' })
})
.then(response => response.json())
.then(data => console.log(data));
```


***

## 최종 체크리스트

```markdown
## Django + MariaDB 보안 체크리스트

### 개발 단계
- [ ] `.env` 파일 생성 & `.gitignore`에 추가
- [ ] `SECRET_KEY` 환경변수로 관리
- [ ] `DEBUG = False` (프로덕션)
- [ ] ALLOWED_HOSTS 지정
- [ ] ORM 사용 (raw 쿼리 최소화)
- [ ] 모든 POST 폼에 `{% csrf_token %}` 추가
- [ ] AJAX는 `X-CSRFToken` 헤더 사용
- [ ] 강력한 비밀번호 정책 설정
- [ ] 권한 검증 데코레이터 사용 (`@require_role` 등)

### 데이터베이스
- [ ] 데이터베이스 사용자 권한 최소화
- [ ] 연결 암호화 (SSL)
- [ ] 정기적 백업 & 무결성 검증
- [ ] 민감 정보는 암호화 저장

### 배포 전
- [ ] HTTPS 인증서 설정
- [ ] 보안 헤더 설정 (HSTS, X-Frame-Options 등)
- [ ] 로깅 시스템 구축
- [ ] 모니터링 & 알림 설정
- [ ] 의존성 버전 고정 (requirements-lock.txt)
- [ ] SAST 스캔 (bandit 등)
- [ ] SCA 스캔 (safety 등)

### 운영 중
- [ ] 정기적 보안 업데이트
- [ ] 로그 모니터링
- [ ] 정기적 보안 감사
- [ ] 침입 탐지 시스템 모니터링
```

이제 Django + MariaDB 스택에서 OWASP Top 10:2025의 모든 항목에 대한 **취약 코드 vs 안전한 코드**를 갖추셨습니다!

특정 부분을 더 깊게 알고 싶거나, 실제 프로젝트에 적용할 때 문제가 생기면 언제든 질문해 주세요. 🔒
<span style="display:none">[^2_1][^2_10][^2_11][^2_12][^2_13][^2_14][^2_15][^2_16][^2_17][^2_18][^2_19][^2_2][^2_20][^2_21][^2_22][^2_23][^2_24][^2_25][^2_26][^2_27][^2_28][^2_29][^2_3][^2_30][^2_31][^2_32][^2_33][^2_4][^2_5][^2_6][^2_7][^2_8][^2_9]</span>

<div align="center">⁂</div>

[^2_1]: https://scientia-tss.com/index.php/journal/article/view/184

[^2_2]: https://aem.az/uploads/posts/2025/01/E.İ. 19.1-103-108.pdf

[^2_3]: https://imanagerpublications.com/article/21781

[^2_4]: https://www.panafrican-med-journal.com/content/article/51/91/full

[^2_5]: https://journals.lib.sfu.ca/index.php/jicw/article/view/6864

[^2_6]: https://gaexcellence.com/jistm/article/view/4883

[^2_7]: https://ieeexplore.ieee.org/document/11289140/

[^2_8]: https://rr.ets.org/index.php/etsrr/article/view/9

[^2_9]: https://ojs.urbe.edu/index.php/telos/article/view/4047

[^2_10]: https://dl.acm.org/doi/10.1145/3701551.3705707

[^2_11]: https://arxiv.org/html/2412.05259v1

[^2_12]: https://arxiv.org/html/2503.00324v1

[^2_13]: https://arxiv.org/pdf/2309.00744.pdf

[^2_14]: https://www.mdpi.com/2673-4591/59/1/1/pdf?version=1702266404

[^2_15]: https://arxiv.org/pdf/2403.15052.pdf

[^2_16]: https://wjaets.com/sites/default/files/WJAETS-2024-0093.pdf

[^2_17]: https://dl.acm.org/doi/pdf/10.1145/3576915.3623072

[^2_18]: https://www.mdpi.com/1424-8220/24/5/1351

[^2_19]: https://escape.tech/blog/best-django-security-practices/

[^2_20]: https://www.stackhawk.com/blog/sql-injection-prevention-django/

[^2_21]: https://docs.djangoproject.com/en/5.2/howto/csrf/

[^2_22]: https://docs.djangoproject.com/en/5.2/topics/security/

[^2_23]: https://stackoverflow.com/questions/20468143/how-can-i-prevent-sql-injection-in-python-django

[^2_24]: https://www.stackhawk.com/blog/django-csrf-protection-guide/

[^2_25]: https://dev.to/topunix/building-a-fort-django-security-best-practices-4fa4

[^2_26]: https://guard-api.com/guides/how-to-fix-sql-injection-in-django/

[^2_27]: https://getdocs.org/Django/docs/3.2.x/ref/csrf

[^2_28]: https://corgea.com/Learn/django-security-best-practices-a-comprehensive-guid-for-software-engineers

[^2_29]: https://www.reddit.com/r/django/comments/bic0i0/sql_injection_will_django_orm_protect_my_website/

[^2_30]: https://django.readthedocs.io/en/latest/howto/csrf.html

[^2_31]: https://www.freecodecamp.org/news/how-to-secure-your-django-app/

[^2_32]: https://jacobian.org/2020/may/15/preventing-sqli/

[^2_33]: https://www.reddit.com/r/django/comments/hv2xya/understanding_csrf_protection_in_django/

