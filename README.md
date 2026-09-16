# 무쓸모

세션 인증 JSON API는 [Notes API 명세](NOTES_API.md)를 참고하세요.

아무것도 하지 않는 클릭과 개인 메모를 기록하는 Flask 서비스입니다.

## 첫 실행

새 데이터베이스에서 관리자 계정을 만들려면 16자 이상의 배포별 비밀번호가
필요합니다. 소스 코드에는 기본 관리자 비밀번호나 관리자 메모 값이 없습니다.

```bash
export ADMIN_PASSWORD='충분히 길고 무작위인 비밀번호'
python app.py
```

첫 실행 시 `admin` 계정과 `SBOB` 접두어를 가진 무작위 전용 메모가 생성됩니다.
고정된 메모가 필요하면 최초 실행 전에 `ADMIN_MEMO`를 설정할 수 있습니다.
이미 생성된 관리자의 비밀번호와 메모는 재시작으로 바뀌지 않습니다.

세션 서명 키는 기본적으로 DB 옆 `.session.key`에 mode 0600으로 생성됩니다.
여러 서버 인스턴스에서는 32자 이상의 동일한 `SECRET_KEY`를 안전한 비밀
관리자에서 공급하세요.

## 운영 설정

- `APP_ENV=production`: 운영 모드
- `COOKIE_SECURE=true`: HTTPS 전용 세션 쿠키. 운영 모드에서는 필수
- `TRUSTED_HOSTS=service.example.com`: 허용할 Host 헤더 목록
- `MAX_USERS`: 전체 회원 상한, 기본 10000
- `LOGIN_IP_LIMIT`, `LOGIN_USER_LIMIT`, `LOGIN_GLOBAL_LIMIT`: 15분 로그인 상한
- `REGISTER_IP_LIMIT`, `REGISTER_GLOBAL_LIMIT`: 1시간 가입 상한
- `AUTH_SESSION_SECONDS`: 서버 측 세션 만료 시간, 기본 1800초

운영에서는 TLS를 종료하는 신뢰할 수 있는 리버스 프록시 뒤에서 실행하고,
`APP_ENV=production`, `COOKIE_SECURE=true`, `TRUSTED_HOSTS`를 명시하세요.
애플리케이션은 전달 헤더를 자동 신뢰하지 않으므로 프록시 설정도 함께 검토해야
합니다.

관리자로 로그인하면 헤더의 **관리자** 메뉴 또는 `/admin`에서 전체 회원 목록과
관리자 전용 메모를 확인할 수 있습니다.

일반 회원을 포함한 모든 로그인 사용자는 홈에서 자기 메모를 작성·조회·삭제할 수
있습니다. 메모는 사용자별로 분리되며 메모당 1,000자, 계정당 100개로 제한됩니다.
