# Design

## Source of truth
- Status: Active
- Last refreshed: 2026-09-15
- Primary product surfaces: 홈, 회원가입, 로그인, 개인 클릭 기록, 개인 메모, 관리자 회원/메모 조회.
- Evidence reviewed: app.py의 기존 단일 HTML, README.md, requirements.txt. 기존 디자인 문서와 이미지 자산 없음.

## Brand
- Personality: 무심하고 장난스럽지만 다정한 휴식 공간.
- Trust signals: 실제 개인 클릭 횟수만 표시, 기능을 솔직하게 설명.
- Avoid: 가짜 통계, 복잡한 대시보드, 과도한 움직임.

## Product goals
- Goals: 방문자가 서비스의 농담을 이해하고 가입, 로그인, 클릭을 쉽게 수행.
- Non-goals: 인증 기능 변경, 생산성 관리 기능 추가.
- Success signals: 핵심 행동이 명확하고 작은 화면에서도 모든 폼을 사용 가능.

## Personas and jobs
- Primary personas: 가볍게 쉬어갈 공간을 찾는 방문자 (기존 카피 기반 가정).
- User jobs: 가입, 로그인, 개인 클릭 횟수 확인 및 증가, 개인 메모 작성·조회·삭제, 로그아웃.
- Key contexts of use: 모바일과 데스크톱 브라우저.

## Information architecture
- Primary navigation: 브랜드 홈 링크와 계정 메뉴.
- Core routes/screens: /, /register, /login, 관리자 전용 /admin. 기존 POST 경로 유지.
- Content hierarchy: 메시지, 주제 문구와 주요 행동, 클릭 장치/인증 폼, 개인 메모, 서비스 철학, 푸터.

## Design principles
- 큰 타이포와 하나의 주요 행동으로 서비스의 단순함을 표현.
- 로그인 상태에서는 실제 횟수를 표시하고 방문자에게는 가입 행동을 제공.
- Tradeoffs: 외부 폰트 대신 시스템 글꼴을 사용하여 로딩과 오프라인 표시 안정성 우선.

## Visual language
- Color: 크림 #f4f2e9, 먹색 #25271f, 주황 #c63b1d, 세이지 #e1e5d6.
- Typography: 시스템 한글 산세리프, 짧은 영문 라벨은 monospace.
- Spacing/layout rhythm: 최대 1320px 외곽, 데스크톱 2열 히어로, 24~70px 섹션 여백.
- Shape/radius/elevation: 얇은 구분선과 작은 라운드, 주 행동만 큰 원형 입체 버튼.
- Motion: hover 및 누름 상태의 짧은 이동, reduced-motion 존중.
- Imagery/iconography: CSS로 만든 클릭 장치와 장식 기호. 의미 없는 기호는 aria-hidden.

## Components
- Existing components to reuse: CSRF 필드, 계정 폼, flash 메시지, 클릭 POST 폼.
- New/changed components: 공통 헤더, 2열 히어로, 입체 버튼, 인증 카드, 개인 메모 작성/목록, 서비스 철학 행.
- Variants and states: 방문자/인증 사용자, 로그인/가입, hover/active/focus.
- Token/component ownership: static/style.css, templates/index.html.

## Accessibility
- Target standard: WCAG AA를 목표로 읽기 쉬운 대비와 폼 구조 제공 (공식 인증 아님).
- Keyboard/focus behavior: 본문 건너뛰기, 기본 폼 키보드 동작, 가시적 focus outline.
- Contrast/readability: 밝은 배경에 어두운 본문, 작은 카피는 보조 정보만.
- Screen-reader semantics: lang=ko, heading 순서, label, aria-describedby, role=status.
- Reduced motion and sensory considerations: reduced-motion 설정에서 전환 제거.

## Responsive behavior
- Supported breakpoints/devices: 950px 중간 레이아웃, 700px 이하 모바일.
- Layout adaptations: 모바일 히어로 및 철학 영역 1열, 보조 헤더 문구 숨김.
- Touch/hover differences: 주요 터치 대상 최소 44px, hover 없이도 기능 인지 가능.

## Interaction states
- Loading: 서버 렌더링 및 기본 브라우저 탐색.
- Empty: 비로그인 홈 000, 새 사용자는 실제 0 표시.
- Error: 기존 flash 검증 오류 표시, 아이디 유지, 비밀번호 재입력.
- Success: 가입/클릭 flash 메시지와 실제 DB 상태 표시.
- Disabled: 별도의 비활성 상태 없음.
- Offline/slow network: 외부 폰트, 이미지, JS에 의존하지 않음. 데이터 변경은 서버 필요.

## Content voice
- Tone: 친근한 존댓말, 생산성 강박을 가볍게 비트는 유머.
- Terminology: 무쓸모, 클릭, 아무것도 안 하기.
- Microcopy rules: 기능은 정확히 설명하고 성공 여부는 실제 응답에 따름.

## Implementation constraints
- Framework/styling system: Flask/Jinja 템플릿과 일반 CSS, 신규 의존성 없음.
- Design-token constraints: CSS :root 공통 색상 사용.
- Performance constraints: CSS 장식만 사용, 외부 요청 없음.
- Compatibility constraints: 기존 인증, DB, CSRF 및 엔드포인트 동작 유지.
- Test/screenshot expectations: 임시 DB 기반 주요 인증/클릭 흐름, 브라우저 가용 시 화면 점검.

## Open questions
- 별도 브랜드 가이드가 없으므로 기존 무쓸모 카피를 기준으로 스타일을 결정함.
