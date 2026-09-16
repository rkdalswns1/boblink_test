# Notes API

## 인증과 CSRF

`POST /login` 폼의 `username`, `password`, `csrf_token`으로 로그인합니다.
먼저 `GET /login`에서 세션 쿠키와 폼의 CSRF 토큰을 받으세요.
로그인 성공 시 세션이 교체되므로 이후 CSRF 토큰은 다시 받아야 합니다.

모든 `/api/*` 요청에는 유효한 로그인 세션 쿠키가 필요합니다.
미인증·만료·로그아웃한 세션은 리다이렉트 없이 JSON `401`을 반환합니다.
인증은 요청 본문과 CSRF 검사보다 먼저 수행합니다.

로그인 후 `GET /api/csrf`는 `200`과 `{"csrf_token":"..."}`을 반환합니다.
API 쓰기 요청에는 해당 토큰을 `X-CSRF-Token` 헤더로 전달하세요.
누락·불일치는 JSON `400`입니다. HTML 폼은 기존 `csrf_token` 필드를 사용합니다.

## 메모 객체

```json
{
  "id": 1,
  "title": "meeting",
  "body": "3pm, room 2",
  "created_at": "2026-09-16 14:02:00",
  "updated_at": "2026-09-16 14:02:00"
}
```

`id`는 정수, 나머지 필드는 문자열입니다. 추가 응답 필드는 허용됩니다.
시간은 UTC의 `YYYY-MM-DD HH:MM:SS` 형식입니다.
수정 API는 없으며 생성 시 두 시각은 같습니다.
기존 HTML 메모는 제목 `메모`, 본문은 기존 내용, 수정 시각은 생성 시각으로 반환합니다.

## 엔드포인트

### GET /api/notes

`200`: `{"notes": [메모 객체, ...]}`. 본인 메모만 ID 내림차순으로 반환합니다.
메모가 없으면 빈 배열입니다. HTML 메모와 API 메모를 합해 계정당 최대 100개이며,
페이지네이션은 제공하지 않습니다.

### POST /api/notes

`Content-Type: application/json`과 `X-CSRF-Token` 헤더가 필요합니다.

```json
{"title": "meeting", "body": "3pm, room 2"}
```

- 요청 본문은 JSON 객체여야 합니다.
- `title`: 필수 문자열. 앞뒤 공백을 제거하고 1~200자여야 합니다.
  빈 문자열과 공백·탭·줄바꿈만 있는 제목을 거부합니다. 제목 중간의 공백은 허용합니다.
- `body`: 선택 문자열, 기본값 `""`, 최대 1,000자. 내용과 공백을 그대로 저장합니다.
- `null`, 숫자, 불리언, 배열, 객체를 제목·본문으로 전달하면 `400`입니다.
- 알 수 없는 요청 필드는 무시합니다. 소유자는 로그인 세션으로만 결정합니다.
- `201`: 생성된 메모 객체를 반환합니다.

### GET /api/notes/<id>

`200`: 본인 메모 객체. 존재하지 않거나 다른 사용자 소유이면 JSON `404`입니다.
관리자도 다른 사용자의 메모를 이 API로 읽을 수 없습니다.

## 오류

모든 `/api/*` 오류 응답은 `{"error":"설명"}` 형태의 JSON입니다.
설명 문구는 고정된 계약이 아닙니다. 인증이 성공한 경우 CSRF를 본문보다 먼저 검사합니다.

| 코드 | 의미 |
| --- | --- |
| 400 | 입력값·JSON 문법 오류, CSRF 누락·불일치 |
| 401 | 유효한 로그인 세션 없음 |
| 404 | 메모 없음·다른 사용자 소유·잘못된 경로 |
| 405 | 지원하지 않는 HTTP 메서드 |
| 409 | 계정당 메모 100개 초과 |
| 413 | 요청 본문이 16 KiB 초과 |
| 415 | JSON이 아닌 Content-Type |

## curl 예제

테스트 계정 `test` / `1235678`이 준비된 로컬 환경을 가정합니다.
`1235678`은 문서·자동 테스트용 값이며 실제 계정을 자동 생성하거나 비밀번호를
변경하지 않습니다. 일반 회원가입은 기존의 12~128자 조건을 유지합니다.
아래 예제는 Bash, curl, Python 3을 사용합니다. 운영 HTTPS 환경에서는 BASE를 바꾸세요.

```bash
BASE=http://localhost:8000
COOKIE=$(mktemp)
chmod 600 "$COOKIE"
trap 'rm -f "$COOKIE"' EXIT

# 로그인 전 폼의 CSRF 토큰과 쿠키를 받습니다.
TOKEN=$(curl -fsS -c "$COOKIE" "$BASE/login" |
  python3 -c 'import re,sys; print(re.search(r"name=\"csrf_token\" value=\"([^\"]+)\"", sys.stdin.read()).group(1))')

curl -fsS -b "$COOKIE" -c "$COOKIE" -o /dev/null \
  --data-urlencode 'username=test' \
  --data-urlencode 'password=1235678' \
  --data-urlencode "csrf_token=$TOKEN" "$BASE/login"

# 로그인 후 교체된 세션의 토큰을 받습니다.
TOKEN=$(curl -fsS -b "$COOKIE" -c "$COOKIE" "$BASE/api/csrf" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')

curl -fsS -b "$COOKIE" "$BASE/api/notes"

NOTE=$(curl -fsS -b "$COOKIE" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $TOKEN" \
  -d '{"title":"meeting","body":"3pm"}' "$BASE/api/notes")
printf '%s\n' "$NOTE"
NOTE_ID=$(printf '%s' "$NOTE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -fsS -b "$COOKIE" "$BASE/api/notes/$NOTE_ID"
```
