# jailscale 설계서

> Java 25 LTS + GraalVM Native Image로 만드는 self-host 터널.
> 노드가 `jailscale open 3000`을 치면 `https://<이름>.<hub 도메인>`이 열리고, 인터넷의
> 브라우저가 노드의 로컬 포트에 닿는다. 방문자는 아무것도 설치하지 않는다.
> hub은 SNI만 보고 바이트를 넘기며, TLS는 노드가 종단하고, 서명만 hub이 해준다.

문서 버전: v4 (2026-09-10)

**변경 이력**

- **v4.1** — 용어를 `open`/`close`/`ls`로. `--registration open`. 노드당 다중 연결(§8). raw TCP/UDP
  포트 공개(§9.5). TCP 프록시 뒤 배치와 PROXY 프로토콜(§9.6). hub 가용성 목표(§7.7).
- **v4 — 제품 방향 전환.** "self-host Tailscale"(피어 메시)에서 "Tailscale Funnel만 있는 것",
  즉 self-host 터널로 범위를 좁힌다. 컨트롤 평면(§6·§7·§11)은 v3을 그대로 잇고 데이터 평면을
  통째로 바꾼다. WireGuard·userspace TCP/IP·NAT 트래버설·DERP·SOCKS5·MagicDNS가 빠지고,
  스트림 멀티플렉서(§8)·SNI 인그레스(§9)·노드 TLS 종단과 서명 위임(§9.3·§10)이 들어온다.
  인증서는 이름마다 받지 않고 **와일드카드 한 장을 hub 내장 DNS-01**로 받는다 (§6.3).
  포트는 TCP 443과 DNS 53뿐이다. v3 문서는 `DESIGN-v3-mesh.md`로 보관한다.
- v3 — 카카오 OAuth 제거. 초대·코드·auth-key·두드리기의 역량 모델로 가입 통일. `/admin`은
  관리자 노드의 MachineKey로 로그인.
- v2 — 리뷰 반영. 자체 HTTP/1.1, Caddy 제거와 내장 ACME, 로컬 IPC, 버전 협상, hub 키 회전,
  경량 예산 CI 게이트.

---

## 1. 목표와 비목표

### 제품 한 줄

로컬에서 도는 것을 인터넷에 HTTPS로 내놓는다. ngrok·Cloudflare Tunnel·Tailscale Funnel이 하는
그 일을, 내 서버 하나와 바이너리 하나로 한다.

### 설계 원칙 (우선순위 순)

1. **경량화 (Lightweight)** — 노드는 상주 데몬이다. 아이들 RSS 20MB 이하, CLI 콜드 스타트 50ms
   이하, 배포물은 런타임 의존성 없는 단일 실행 파일. hub도 단일 바이너리이며 아이들 RSS 50MB
   이하. 수치는 M0에서 실측하고 CI 게이트로 지킨다 (§4).
2. **사용성 (Usability)** — 공개하는 사람은 `jailscale open 3000` 한 줄. 초대하는 사람은
   `jailscale invite` 한 줄. 방문자는 URL 하나. hub 운영자의 사전 준비는 DNS 레코드 셋과 방화벽
   뿐이며(§6.3), 그 목록을 늘리는 변경은 이 원칙에 대한 위반으로 취급한다. 브라우저 로그인도
   계정도 IdP도 없다.
3. **범용성 (Portability)** — root 권한 불필요, TUN 불필요, 커널 모듈 불필요. UDP도 노드 쪽에는
   불필요하다. native 바이너리를 못 쓰는 환경을 위해 순수 JVM fallback JAR도 항상 함께 배포한다.

### 비목표

- 노드끼리의 사설 연결(메시 VPN). `ssh laptop`이나 사설 NAS 접근은 이 제품이 아니다.
  컨트롤 평면이 그대로이므로 나중에 데이터 평면을 하나 더 얹는 형태로 되돌릴 수 있다 (§15).
- 공식 Tailscale·ngrok·frp와의 와이어 호환성
- 방문자 쪽 HTTP/2·HTTP/3. 브라우저는 HTTP/1.1로 잘 붙고, 노드 뒤의 로컬 앱은 대개 h1이다.
- Android / iOS 클라이언트

---

## 2. 구성 요소 개요

```
   방문자 브라우저                        jailhub (단일 프로세스)                        jailscale 노드
   https://myapp.hub.example.com     ┌──────────────────────────────────┐          ┌──────────────────────┐
          │                          │  :443  SNI 라우터                 │          │  TLS 종단 (SSLEngine) │
          │  TLS ClientHello         │   ├ hub.example.com → 자기 HTTP   │  mux     │   ├ 서명은 hub에 위임  │
          ├─────────────────────────►│   ├ *.hub.example.com → 노드 스트림├─────────►│   ├ 방문자 게이트      │
          │  (암호문 그대로 통과)      │   └ 사용자 도메인 → 노드 스트림    │  Noise   │   └ 평문 → 127.0.0.1:3000
          │                          │                                  │  in TLS  │                      │
          │                          │  Coordinator  초대·이름·승인       │◄─────────│  CLI ↔ 데몬 (AF_UNIX) │
          │                          │  ACME         와일드카드 + DNS-01  │          └──────────────────────┘
          │                          │  :53   _acme-challenge TXT 응답   │
          │                          │  Admin        IPC + /admin 웹      │
          │                          │  서명 서비스   와일드카드 키 보관    │
          │                          └──────────────────────────────────┘
```

**핵심 결정 세 가지.**

- **hub은 SNI만 본다.** 공개 443으로 들어온 TLS 연결에서 ClientHello의 SNI를 읽고, 그 이름이
  배정된 노드로 바이트 스트림을 넘긴다. hub은 방문자 트래픽의 HTTP를 파싱하지 않는다.
  인터넷에 노출된 hub의 공격면이 TCP 수준으로 줄고, hub은 암호문만 본다.
- **노드가 TLS를 종단하되 키는 hub에 있다.** 이름은 `*.hub.example.com` 와일드카드 인증서
  한 장으로 다 덮는다. 개인키는 hub을 떠나지 않으며, 노드는 핸드셰이크의 서명 한 번을 컨트롤
  채널로 hub에 부탁한다. 서명은 hub이 그 노드에 배달한 스트림에 묶인다 (§9.3).
- **노드도 HTTP를 파싱하지 않는다.** TLS를 벗긴 평문을 로컬 포트로 그대로 흘린다. HTTP/1.1이든
  WebSocket이든 로컬 앱이 처리한다. 시스템 전체에서 HTTP 파서는 컨트롤 채널용 소형 하나와,
  방문자 게이트를 켰을 때 첫 요청의 헤더를 읽는 것뿐이다.

**포트.** TCP 443(전부), UDP/TCP 53(ACME DNS-01 응답 전용). TCP 80은 선택이다(HTTPS 리디렉트,
사용자 도메인의 HTTP-01 중계). raw TCP/UDP 공개를 쓰려면 포트 범위 하나가 더 열린다 (§9.5).
노드 쪽은 아웃바운드 443 하나다.

**용어.** 노드가 로컬 포트를 인터넷에 내놓은 것을 **공개 링크**(줄여서 링크)라 부른다.
`jailscale open`으로 열고 `close`로 닫으며 `ls`로 본다. 초대 링크(§11)와 방문 링크(§10.4)는
다른 것이다.

---

## 3. 모듈 레이아웃

Maven 멀티모듈. 의존 방향은 위에서 아래로만 흐른다.

```
jailscale/
├── pom.xml                  parent (release=25, native 프로파일)
├── jailscale-crypto/        BLAKE2s · HKDF · X25519 · ChaCha20-Poly1305 · Noise IK · 키 타입/인코딩
├── jailscale-proto/         컨트롤 메시지 + JSON 코덱 + mux 프레이밍 + 최소 HTTP/1.1 파서 + SNI 파서 (crypto 의존)
├── jailscale-node/          데몬 + CLI + 로컬 IPC + TLS 종단 + 원격 서명 Provider + 게이트  → 바이너리 `jailscale`
└── jailscale-hub/           SNI 라우터 + coordinator + ACME/DNS + 서명 서비스 + 관리 IPC/웹   → 바이너리 `jailhub`
```

v3에 있던 `jailscale-wire`(WireGuard)와 `jailscale-netstack`(userspace TCP/IP)은 없다. 바이너리를
둘로 나누는 이유는 클라이언트에 서버 코드가 섞이지 않게 해서 배포물을 작게 유지하기 위함이다.
모듈 경계를 명시해 두면 의존성 역류를 컴파일 타임에 막을 수 있다.

---

## 4. GraalVM Native Image 규율

이 프로젝트의 모든 코드는 아래 규칙을 따른다. 나중에 고치는 게 아니라 처음부터 지킨다.

| 항목 | 규칙 | 이유 |
|---|---|---|
| 리플렉션 | 금지 | reachability metadata 관리 비용, 바이너리 비대화 |
| 동적 프록시 / 클래스로딩 | 금지 | native-image에서 사실상 불가 |
| DI 프레임워크 | 사용 안 함. 생성자 수동 배선 | Spring/Guice는 리플렉션 덩어리 |
| JSON | 자체 파서 + 수동 인코더 (`jailscale-proto`) | Jackson은 리플렉션 + 수 MB 증가. 메시지 스키마가 10여 개뿐이라 수동이 싸다 |
| HTTP 서버 | **자체 최소 HTTP/1.1** (`jailscale-hub`, 자기 이름의 5개 엔드포인트만) | JDK `com.sun.net.httpserver`는 Upgrade 후 소켓을 내주지 않는다. 방문자 트래픽은 HTTP를 파싱하지 않으므로 이것으로 충분하다 |
| HTTP 클라이언트 | 노드: `SSLSocket` 위 자체 소형 HTTP/1.1 (~40줄). hub: JDK `java.net.http.HttpClient` (ACME) | 노드는 Upgrade가 필요해 JDK 클라이언트를 못 쓴다. 덕분에 노드 바이너리에서 `java.net.http`가 빠진다 |
| TLS | JDK JSSE. hub은 `SSLServerSocket`(자기 이름), 노드는 `SSLEngine`(방문자 스트림) | 이미 바이너리에 있다 |
| 원격 서명 | 자체 JCE `Provider` + 불투명 `PrivateKey` + `Signature` SPI | PKCS#11 키가 쓰는 경로. `Provider.Service.newInstance` 재정의로 리플렉션 없이 등록 (§10.2) |
| ACME 클라이언트 · DNS 응답기 | 자체 구현 (`jailscale-hub`, ~700줄) | JWS ES256·JSON·HttpClient는 JDK와 우리 코드로 충분. CSR DER 인코딩과 DNS TXT 응답만 손수 쓴다 (§6.3) |
| 로깅 | 자체 초경량 로거 (`System.Logger` 백엔드) | SLF4J+logback은 ServiceLoader + 리플렉션 |
| 암호 | JDK JCE (SunEC의 X25519, SunJCE의 ChaCha20-Poly1305) + 자체 BLAKE2s·HMAC·HKDF | BouncyCastle은 native 설정이 번거롭고 크다. 원시 함수는 JDK 것을 쓴다. 직접 짜는 셋은 선택이 아니라 필연이다: JDK에 BLAKE2s가 없고, Noise는 HMAC과 HKDF를 고른 해시 위에 정의하므로 BLAKE2s를 고르면 둘이 딸려온다. Noise의 HKDF는 RFC 5869과도 다르다 (salt/info 대신 출력 카운터 바이트, 최대 3단 연쇄) |
| AWT / `java.awt.Desktop` | 금지 | 브라우저 열기는 `open` / `xdg-open` / `rundll32 url.dll,FileProtocolHandler`를 `ProcessBuilder`로 |
| 프로세스 간 통신 | AF_UNIX 소켓 (`UnixDomainSocketChannel`, 모든 플랫폼) | Windows 10 1803+도 AF_UNIX를 지원한다. 명명된 파이프는 JDK 공개 API가 없다 |
| 스레딩 | Virtual threads 전면 사용 | 패킷 핫패스가 없어졌다. 스트림당 virtual thread면 충분하다 (§13) |
| 빌드 시 초기화 | 화이트리스트 방식으로 신중히. JCE는 런타임 초기화 | 빌드 타임에 SecureRandom 시드가 고정되는 사고 방지 |

**빌드**

- 빌드 도구는 **Maven**이다. 서드파티 의존성이 0개라 Gradle의 유연한 의존성·빌드 로직이 살
  일이 없고, 고정된 생명주기가 5개 플랫폼에서 어긋날 여지를 줄인다. `native-maven-plugin`은
  GraalVM 팀이 직접 관리한다. 빌드가 1분이라 Gradle의 증분·데몬 이점도 크지 않다.
- `./mvnw`는 **only-script** 모드다. Gradle Wrapper와 달리 저장소에 바이너리 jar를 커밋하지
  않는다. 서명된 바이너리를 배포하는 프로젝트가 출처를 스스로 확인할 수 없는 jar를 저장소에
  두지 않기 위해서다. 받아오는 Maven 배포본은 `distributionSha256Sum`으로 고정한다. 그 값은
  Maven Central이 공개한 sha512로 무결성을 확인한 바이트에서 뽑았고, 틀린 값을 넣으면 wrapper가
  실행을 거부하는 것까지 확인했다. 공급망 표면을 0으로 유지하는 것이 이 표 전체의 목적이다.
  Maven 버전을 올리면 이 값도 같이 바꿔야 한다.
- 기본 프로파일: 일반 JVM 빌드 (`mvn test` 빠른 반복)
- `-Pnative`: `native-maven-plugin`으로 바이너리 생성
- CI 매트릭스: linux-amd64, linux-arm64, macos-arm64, macos-amd64, windows-amd64
- 매 릴리스마다 fallback으로 `jailscale-all.jar` (JVM 25 필요) 동봉 → **범용성 보증**

**경량 예산 게이트 (M4에서 확정. `./measure.sh --check`, 값은 스크립트 상단과 이 표가 같아야 한다)**

| 측정 | 게이트 | 방법 |
|---|---|---|
| 노드 아이들 RSS | ≤ 28 MB | native `jailscale`이 hub에 붙어 공개 링크 하나를 연 뒤 10초 유휴 |
| hub 아이들 RSS | ≤ 30 MB | 노드 2대, 링크 하나, 유휴 |
| 부하 중 RSS | 노드·hub 각 ≤ 64 MB | `LOAD=1000`: 방문자 1,000명이 동시에 https로 링크를 친 직후 |
| 바이너리 크기 | ≤ 30 MiB | 릴리스 아티팩트 |
| CLI 콜드 스타트 | ≤ 50 ms | `jailscale status` 10회 중앙값 (IPC 왕복 포함) |
| 방문자 핸드셰이크 지연 | 기록만 | M2 실측 2.3 ms(단독), M4 부하에서 0.5 ms/건(1,000건 병렬) |

원래 목표였던 노드 20 MB는 §15에 남긴다(현재 24.8 MB, JSSE 이미지 힙이 대부분). 게이트는 현재 실측에
여유를 둔 값이며, 넘으면 스크립트가 실패한다. 예산은 이유와 함께 PR로만 바꾼다.

**개발 환경 요구사항**

- `brew install graalvm` → GraalVM CE 25.3.x (JDK 25.0.x, GPL+CPE, native-image 포함). keg-only라
  PATH에 오르지 않으므로 native 빌드 시 `JAVA_HOME=/opt/homebrew/opt/graalvm/libexec/graalvm.jdk/Contents/Home`
  으로 실행한다 (`./native.sh` 참조). 일반 빌드와 테스트는 JDK 25.0.3 이상이면 된다.
- **JDK 25.0.0~25.0.2는 쓰지 않는다.** JDK 25가 가상 스레드의 timed park를 ForkJoinPool의 지연
  작업으로 옮기면서(JDK-8351927) 두 회귀가 들어왔다. 지연 작업을 취소하면 스케줄러의 힙이 깨져
  다른 스레드의 `Thread.sleep`이 몇 배 늦거나 한참 안 깨어나고(JDK-8370887), 가상 스레드가
  PARKED에 갇힌다(JDK-8369227). 둘 다 25.0.3에서 고쳐졌다. hand-off는 옛 연결의 keepalive
  sleep을 interrupt로 취소하므로 정확히 그 경로를 밟으며, `HandoffTest`가 GraalVM CE 25.0.2 +
  3코어에서 30회 중 5회 그 모양(응답이 4~5 조각에서 멈추고 앱의 `sleep(250)`이 19초째
  TIMED_WAITING)으로 실패했다. 25.0.4.1에서는 30회 이상 무재현. 릴리스 워크플로가 이 때문에
  Liberica NIK(`setup-graalvm`의 `distribution: liberica`, JDK 25.0.4+)를 쓴다: 그 액션의
  `graalvm-community`는 `jdk-25.0.2` 태그 줄기만 보고(Innovation 빌드는 못 고른다) macOS x64는
  25.0.1 이후 빌드가 없다. Homebrew의 graalvm(25.3.x)은 JDK 25.0.3 이상이라 로컬은 무관하다.
- **Windows에서 가상 스레드가 양방향 루프백 읽기를 놓친다.** Windows·가상 스레드·양방향 트래픽
  셋이 겹치면 읽기 쪽이 park된 채 깨어나지 않는다. 늦게 깨어나는 것이 아니라 영영 깨어나지 않는다(건당 제한 10초에서 42.7%, 150초에서 40.0%로 비율이 같다). 의존성 없는 재현기와 측정은
  `docs/windows-virtual-thread-stall/`에 있다. 25.0.4에서도 나므로 앞의 두 회귀와는 별건이고,
  jailscale 코드 없이도 나온다(재현기 39.5% 대 `MuxSession` 경유 1.8%). 고칠 수 있는 것이
  아니라서 감지·복구로 둔다. mux 소켓의 60초 읽기 타임아웃(§7)과 25초 KEEPALIVE(§8)가 그 역할을
  하며, 실제로 발생하면 `peer idle too long`으로 세션이 닫히고 노드가 재접속한다.
- native-maven-plugin의 reachability metadata 저장소는 끈다. 외부 의존성이 없고 리플렉션도
  없으므로 가져올 것이 없다.
- Linux에서는 `gcc`, `zlib` 개발 헤더 필요
- Maven은 설치하지 않는다. 레포의 `./mvnw`(Maven Wrapper 3.3.4, only-script)가 3.9.16을 받아
  쓴다. 버전은 junit-bom 6.1.3, maven-compiler-plugin 3.16.0(`-Xlint:all -Werror`), surefire 3.6.0,
  native-maven-plugin 1.1.12 (2026-09-10 Maven Central 기준). `./mvnw -Pnative package`가 node·hub
  바이너리를 만들고 crypto·proto는 `native.skip=true`로 건너뛴다.

---

## 5. 키와 신원

| 키 | 소유 | 용도 | 수명 |
|---|---|---|---|
| **MachineKey** (`mkey:`) | 노드 | 컨트롤 채널 Noise 핸드셰이크의 클라이언트 정적 키. 이 머신의 신원이자 `/admin` 로그인 신원 | 머신 수명 전체 |
| **hkey** (`hkey:`) | hub | 컨트롤 채널 Noise 핸드셰이크의 서버 정적 키. 노드가 고정(pin)한다 | 회전 절차 있음 (§6.2) |
| **와일드카드 인증서 키** | hub | `hub.example.com` + `*.hub.example.com` ECDSA P-256. **hub을 떠나지 않는다.** 노드는 서명만 위임받는다 | ACME 갱신마다 새 키 |
| **사용자 도메인 키** | 노드 | `myapp.com`처럼 사용자가 가져온 도메인의 인증서 키. hub에 없다 | 노드의 ACME 갱신마다 |

v3의 NodeKey(WireGuard)와 DiscoKey(경로 탐색)는 데이터 평면과 함께 사라졌다. 노드의 신원은
MachineKey 하나다. 노드 ID와 이름 배정은 MachineKey에 묶이며, 다른 사용자의 초대로 다시 가입하면
소유자만 바뀐다.

**인코딩.** `prefix:base64url-nopad`. 프리픽스가 있으면 로그·설정 파일에서 키 종류를 눈으로
구분할 수 있고, 잘못된 자리에 붙여넣는 사고를 파싱 단계에서 잡는다.

**저장 위치.** 노드: `$XDG_CONFIG_HOME/jailscale/node.json` (기본 `~/.config/jailscale/`), 0600.
Windows는 `%LOCALAPPDATA%\jailscale\`이며 현재 사용자만 읽는 ACL. 사용자 도메인 키는 같은
디렉터리의 `domains/<domain>.key`.

---

## 6. 컨트롤 채널 (`jailscale-hub` ↔ `jailscale-node`)

### 6.1 전송 계층: TLS 위의 Noise (심층 방어)

노드 ↔ hub 통신은 **웹 PKI TLS 연결 안에서 Noise_IK 채널을 다시 여는** 이중 구조다.
운반체는 HTTP/1.1 Upgrade이며, 101 이후는 그냥 바이트 스트림이다. 이 스트림 위에 §8의
멀티플렉서가 올라간다.

```
TCP 443, SNI = hub.example.com
 └─ TLS 1.3, ALPN http/1.1   (웹 PKI. 호스트명을 인증하고 최초 신뢰를 부트스트랩)
     └─ HTTP/1.1 Upgrade   POST /v1/noise, Upgrade: jailscale-control-v1
         └─ Noise_IK       (MachineKey ↔ hkey. CA를 신뢰하지 않아도 성립)
             └─ [2B len BE][Noise transport 메시지]   ← 안에 mux 프레임 (§8)
```

**JDK의 HTTP 스택은 여기에 쓸 수 없다.** `com.sun.net.httpserver`는 Upgrade 후 소켓을
핸들러에 내주지 않고, `java.net.http.HttpClient`도 101 응답 이후의 연결을 넘겨주지 않는다.
따라서 양쪽 모두 손수 쓴다.

- **hub**: SNI 라우터(§9.1)가 자기 이름으로 온 연결을 넘겨주면 `SSLServerSocket` 위의 최소
  HTTP/1.1 서버가 받는다. 엔드포인트는 `/v1/key`, `/v1/noise`, `/join/*`, `/admin/*`,
  `/.well-known/acme-challenge/*`(사용자 도메인 중계용, §9.4) 다섯이다. `/v1/noise`는 101을 쓴 뒤
  소켓을 Noise 핸들러에 넘긴다. 300줄 안팎.
- **노드**: `SSLSocket` 위의 소형 HTTP/1.1 클라이언트. 요청 한 줄과 헤더 몇 개를 쓰고 응답 줄을
  파싱한다. 40줄 안팎. `/v1/key` GET도 이 클라이언트로 처리하므로 **노드 바이너리에는
  `java.net.http` 모듈이 들어가지 않는다.**

**WebSocket을 쓰지 않는 이유.** JDK 클라이언트가 내장이라는 장점은 40줄짜리 클라이언트 앞에서
의미가 없고, 클라이언트→서버 프레임의 4바이트 XOR 마스킹이 모든 방문자 바이트를 한 번 더
만지게 하며, 프레임 헤더·조각화·close 의미론이 따라온다. `Upgrade: websocket`만 통과시키는
Cloudflare 프록시 뒤는 지원하지 않는다. 어차피 SNI 통과가 필요해 hub 앞에 HTTP 프록시를 둘 수
없다 (§6.3).

ALPN을 `http/1.1`로 고정하는 이유: HTTP/2에는 Upgrade가 없다. `SSLParameters`로 직접 지정한다.

**Noise 파라미터.** `Noise_IK_25519_ChaChaPoly_BLAKE2s`, 프롤로그 `jailscale-control-v1`.
프롤로그의 버전 문자열은 핸드셰이크 해시에 섞이므로 호환되지 않는 버전끼리는 핸드셰이크
자체가 실패한다. Noise transport 메시지는 최대 65535B이며 길이 프리픽스가 2바이트인 이유다.

**왜 TLS를 벗기지 않는가.** Noise만으로도 컨트롤 채널은 인증된다. 그럼에도 TLS인 이유는 셋이다.
(1) hkey 부트스트랩: 노드가 호스트명만 알고 접속하려면 첫 접촉에서 hub 키를 믿을 근거가
필요하고 그것이 웹 PKI다. (2) `/join`과 `/admin`은 브라우저가 가는 경로다. (3) 기업 방화벽은
443의 TLS는 통과시키지만 정체불명의 바이너리 스트림은 차단한다. 인증서는 hub이 스스로
받으므로 운영자 비용이 없다. 그리고 공개 443 자체가 TLS라 컨트롤 채널만 벗길 이유가 없다.

**왜 그런데도 Noise를 안에 넣는가.** 웹 PKI의 위협 모델에는 CA 침해와 사내 루트 CA를 설치한
기업 MITM 프록시가 남는다. 그 둘은 TLS를 뚫지만 고정된 hkey로 수행하는 Noise 핸드셰이크는
뚫지 못한다. Tailscale의 ts2021과 같은 구조다. 그리고 §9.3의 **서명 위임이 이 채널로 흐른다.**
와일드카드 키의 서명 요청·응답이 지나가는 통로이므로 CA에 의존하지 않는 인증이 필요하다.

### 6.2 hub 키 부트스트랩과 회전

노드가 알아야 하는 것은 **호스트명 하나뿐**이다 (초대 링크에 들어 있다).

```
1. jailscale up --invite https://hub.example.com/join/…
2. GET https://hub.example.com/v1/key         ← 평범한 TLS, 웹 PKI로 검증
     → { "hubKey": "hkey:...", "nextHubKey": null, "notAfter": 1789000000 }
3. 노드가 그 키를 node.json에 고정(pin)
4. POST https://hub.example.com/v1/noise      ← TLS 안에서 HTTP/1.1 Upgrade
     → 고정된 hkey로 Noise_IK 개시
5. 이후 모든 접속은 고정된 키를 사용. 불일치는 경고와 함께 하드 실패
```

**회전.** `notAfter`는 hub 키의 만료 예정 시각이다.

1. 운영자가 `jailhub key rotate --grace 30d`를 실행하면 hub이 `next` 키를 생성한다.
2. 이후 붙는 모든 노드에게 컨트롤 채널로 `HubKeyRotation{ nextHubKey, activatesAt }`를 보낸다.
   옛 키로 인증된 Noise 채널 안에서 오므로 별도 서명이 필요 없다. 노드는 `next`를 함께 저장한다.
3. 유예 기간 동안 hub은 두 키 모두로 핸드셰이크를 받는다. 노드는 `current`로 시도하고 실패하면
   `next`로 재시도한다.
4. `activatesAt` 이후 hub은 옛 키를 버린다.
5. 유예 기간 동안 한 번도 접속하지 않은 노드는 두 키 모두 실패한다. 이 경우에만 노드는
   "hub 키가 바뀌었습니다. 다시 신뢰하시겠습니까 (y/N)"를 물은 뒤 `/v1/key`로 재부트스트랩한다.
   무인 노드는 실패 상태로 남고 로그에 이유를 남긴다.

**강화 옵션 `--hub-key hkey:...`** — 웹 PKI를 신뢰하지 않는 배포와 에어갭용. `/v1/key` 조회를
건너뛰고 Noise가 서버 인증을 완결하므로 컨트롤 채널에 한해 TLS 검증을 완화해도 보안 손실이
없다. 클릭 가능한 `https://...?key=` 형태로 키를 전달하는 것은 금지한다. 링크처럼 생긴 것은
사람이 검증하지 않는다. 초대 링크는 비밀값이라 링크가 정상 수단이고, hub 공개키는 검증해야
하는 공개값이라 링크가 부적절한 수단이다.

### 6.3 인증서: 와일드카드 한 장, hub 내장 DNS-01

**이름마다 인증서를 받지 않는다.** Let's Encrypt는 등록 도메인당 주 50개의 신규 인증서
한도가 있다. `jailscale open 3000`이 매번 임의 이름을 만드는 UX에서는 하루 만에 소진되고,
이름이 처음 열릴 때마다 ACME 왕복 수 초 동안 HTTPS가 안 된다. 와일드카드 한 장이면 발급은
두 달에 한 번이고 새 이름은 0초에 열린다.

와일드카드는 DNS-01로만 받을 수 있다. 보통 이것은 DNS 제공자 API 토큰을 뜻하지만, 우리는
**hub이 `_acme-challenge` 이름의 권한 DNS 서버가 된다** (acme-dns 패턴). 운영자가 만드는
레코드는 셋이다.

```
hub.example.com.                  A   203.0.113.10        ← 프록시 없이 직접 (Cloudflare는 DNS only)
*.hub.example.com.                A   203.0.113.10
_acme-challenge.hub.example.com.  NS  hub.example.com.    ← NS 대상이 위임 영역 밖이라 글루 불필요
```

CA가 `_acme-challenge.hub.example.com`의 TXT를 물으면 위임을 따라 hub의 53 포트로 오고, hub이
그 순간의 챌린지 값을 답한다. 이 하나의 이름이 `hub.example.com`과 `*.hub.example.com` 두 SAN의
검증을 모두 담당한다.

**hub 운영자의 사전 준비는 이것이 전부다.**

| # | 준비 | 비고 |
|---|---|---|
| 1 | DNS 레코드 셋 (위) | 어떤 DNS UI에서든 만들 수 있다 |
| 2 | 방화벽: TCP 443, UDP 53, TCP 53 | 80은 선택 (HTTPS 리디렉트 · 사용자 도메인 HTTP-01 중계). raw 포트 공개를 쓰면 `--port-range`(기본 10000-10999) TCP/UDP 추가 (§9.5) |

첫 실행은 `jailhub serve --base-url https://hub.example.com` 한 줄이며, 콘솔에 첫 초대 링크가
찍힌다 (§11.5).

**내장 ACME의 동작**

```
jailhub serve --base-url https://hub.example.com
 │
 ├─0. $JAILHUB_STATE/tls/ 에 유효한 와일드카드 인증서가 있으면 → 즉시 443 개방, 8번으로
 ├─1. 53 포트 응답기 기동. _acme-challenge.hub.example.com 의 TXT·SOA·NS 만 답한다.
 │     그 외 질의는 REFUSED. 공인 IP에만 바인드 (127.0.0.53의 systemd-resolved와 충돌 회피)
 ├─2. 자가 진단 (통과해야 발급 시작. 실패하면 원인을 콘솔에 출력하고 60초마다 재시도)
 │     · 공용 리졸버(1.1.1.1, 8.8.8.8)에 _acme-challenge.hub.example.com TXT 를 물어
 │       내가 방금 넣은 무작위 값이 돌아오는지 확인 → NS 위임 누락 / 53 차단 / 캐시 를 구분
 │     · hub.example.com 과 임의의 *.hub.example.com 이 내 공인 IP로 풀리는지 확인
 │       → Cloudflare "Proxied"(주황 구름)면 엣지 IP가 나와 여기서 잡힌다
 │     · 가정용 공유기 뒤처럼 헤어핀이 안 되는 곳은 --no-selfcheck 로 건너뛴다
 ├─3. 계정 키(EC P-256) 없으면 생성 → tls/account.key (0600). newAccount, 약관 동의
 ├─4. newOrder { identifiers: [dns: hub.example.com, dns: *.hub.example.com] }
 ├─5. 두 authorization 의 dns-01 챌린지 token → TXT 값 = base64url(SHA-256(keyAuthorization))
 │     → 53 응답기에 등록 (두 값을 같은 이름의 TXT 레코드 두 개로)
 ├─6. 챌린지 "준비됨" POST. CA가 여러 지점에서 53으로 확인. authorization 폴링 (최대 60초)
 ├─7. 인증서 키(EC P-256) 생성 → PKCS#10 CSR DER 직접 인코딩 → finalize → 체인 다운로드
 │     → tls/wildcard.key, tls/wildcard.pem (0600)
 ├─8. 443 개방. 인증서(공개 부분)를 접속 중인 모든 노드에 CertUpdate 로 push (§7)
 └─9. 갱신: 하루 한 번 검사, 잔여 수명이 전체의 1/3 이하이면 4~8 반복. 새 키와 인증서로
        교체하되 옛 키는 24시간 더 유지 (노드가 옛 인증서로 진행 중인 핸드셰이크 대비).
        실패 시 지수 백오프, 만료 7일 전부터 콘솔과 /admin 에 경고
```

- **JWS.** 보호 헤더 `{alg: ES256, nonce, url, jwk|kid}`. JDK `SHA256withECDSA`는 DER 서명을
  내주므로 JWS의 raw `R||S` 64바이트로 변환한다. 빠뜨리면 CA가 모든 요청을 거부한다.
- **CSR.** JDK에는 PKCS#10 공개 API가 없다. 최소 DER 작성기(~80줄) 위에
  `CertificationRequestInfo{version 0, subject CN, SubjectPublicKeyInfo, extensionRequest[SAN×2]}`를
  만들고 ECDSA로 서명한다 (~120줄).
- **DNS 응답기.** 질의 파싱과 TXT/SOA/NS 응답 조립 ~150줄. EDNS0는 512B 이하 응답이라 무시해도
  된다. UDP와 TCP 둘 다 받는다(CA는 UDP 우선, TCP 폴백).
- **ECDSA를 고르는 이유.** 노드가 위임받는 개인키 연산이 **서명 하나**뿐이게 하기 위해서다.
  RSA 키 교환은 복호화가 필요하므로 그 스위트를 끈다 (§9.3).
- **지원 범위.** ACME v2, dns-01만. External Account Binding(ZeroSSL 등)은 v1 밖.
- **직접 주는 인증서** `--tls-cert/--tls-key`: 사내 CA나 53을 열 수 없는 환경. 와일드카드 SAN이
  있어야 하며, 파일 변경 감지 시 리로드하고 노드에 push한다.
- **포트 바인딩 권한.** Linux에서 443/53은 root 또는 `CAP_NET_BIND_SERVICE`. 참조 systemd
  유닛은 전용 사용자 `jailhub` + `AmbientCapabilities`로 root 없이 띄운다. macOS는 비특권
  바인딩이 허용된다.
- **앞에 HTTP 프록시는 둘 수 없고, TCP 프록시는 둘 수 있다.** SNI 통과에는 raw TCP 443이
  필요하다. TLS를 종단하는 HTTP 리버스 프록시(nginx `http`, Caddy, Cloudflare Proxied)는
  성립하지 않는다. TLS를 열지 않고 바이트만 넘기는 4계층 프록시(nginx `stream`, HAProxy
  `mode tcp`)는 지원하며 참조 설정을 배포물에 동봉한다 (§9.6).

---

## 7. 컨트롤 API

멀티플렉서(§8)의 **스트림 0**에 실리는 JSON 메시지. 모든 메시지는 `{"t": "<타입>", ...}`.

| 메시지 | 방향 | 역할 |
|---|---|---|
| `Hello` | N→H | **핸드셰이크 직후 첫 메시지.** `proto`(정수), `version`, `os`, `conn`(연결 번호, §8) |
| `HelloResponse` | H→N | `proto`, `minProto`, `version`, `dnsSuffix`. 노드의 `proto < minProto`면 `Goodbye` |
| `Goodbye` | 양방향 | `reason`: `upgrade-required`, `revoked`, `shutdown` |
| `RegisterRequest` | N→H | hostname·os 제출. `invite`, `code`, `authKey` 중 하나를 동봉하거나 없음(두드리기) |
| `RegisterResponse` | H→N | `approved{nodeId, user}` 또는 `pending` 또는 `rejected{reason}` |
| `CertUpdate` | H→N | 와일드카드 인증서 체인(공개 부분)과 `keyId`. 접속 직후와 갱신 시 |
| `LinkOpen` | N→H | 공개 요청. `kind: https\|tcp\|udp`, `name?`(없으면 임의), `domain?`(사용자 도메인), `port?`(raw 공개 시 희망 포트) |
| `LinkOpened` | H→N | `linkId`, `name`, `url` 또는 `hubPort`, 또는 `rejected{reason: taken \| not-owner \| domain-unverified \| no-port}` |
| `LinkClose` | N→H | 공개 해제 (이름·포트 소유권은 유지) |
| `SignRequest` | N→H | `streamId`, `keyId`, `alg`, `digest` (§9.3) |
| `SignResponse` | H→N | `streamId`, `sig` 또는 `rejected{reason}` |
| `ChallengeSet` / `ChallengeClear` | N→H | 사용자 도메인 HTTP-01의 token → keyAuthorization 등록·해제 (§9.4) |
| `InviteCreate` / `InviteCreated` | N→H / H→N | 멤버 노드의 초대 발급 (§11.2) |
| `AdminLink` | N→H / H→N | 관리자 노드의 `/admin` 일회용 로그인 URL (§7.6) |
| `HubKeyRotation` | H→N | §6.2 |
| `Ping` / `Pong` | 양방향 | 요청 시 왕복 측정 (`jailscale netcheck`). 생존 확인은 §8의 `KEEPALIVE` |

**버전 정책.** `proto`는 메시지 스키마와 mux 프레임 집합의 버전이다. hub은 `minProto` 이상을
받는다. 노드가 hub보다 새 `proto`를 말하면 hub의 `proto`로 낮춰 동작한다. 프롤로그 문자열의
숫자는 Noise 파라미터가 바뀔 때만 올린다.

### 7.5 저장소

**파일 기반.** append-only JSON Lines 이벤트 로그 + 인메모리 상태. 재시작 시 리플레이.

```
$JAILHUB_STATE/          (기본 /var/lib/jailhub 또는 ~/.local/share/jailhub)
├── hub.key              hub 정적 개인키 (0600). 회전 중이면 hub.key.next도 존재
├── state.jsonl          이벤트 로그 (node-registered, name-claimed, invite-created, ...)
├── state.snapshot       주기적 스냅샷 (로그 압축)
├── jailhub.lock         프로세스 락. 두 번째 jailhub serve는 즉시 실패
├── jailhub.sock         관리 IPC 소켓 (§7.6)
└── tls/                 account.key · wildcard.key · wildcard.pem · wildcard.key.prev (0600)
```

- 이벤트는 쓰기 후 `fsync`. 스냅샷은 임시 파일에 쓰고 `rename`으로 원자 교체.
- 상태 디렉터리에 쓰는 프로세스는 `jailhub serve` 하나뿐이다. 관리 명령은 IPC로 서버에 요청한다.
- 인메모리 상태: 노드(MachineKey → 소유자·호스트명·온라인), 이름(name → 소유 노드·활성 여부),
  사용자 도메인(domain → 소유 노드·검증 여부), 초대·auth-key 해시, 관리자, 대기 큐.
  수천 이름까지는 맵이 압도적으로 단순하다. 규모가 필요해지면 `Store` 인터페이스 뒤에 Postgres.

### 7.6 관리 IPC와 관리 웹

`jailhub node approve`, `jailhub invite create`, `jailhub key rotate` 같은 관리 명령은 별도
프로세스다. 상태가 인메모리이므로 **실행 중인 서버에 요청**해야 한다.

- 전송: AF_UNIX 소켓 `$JAILHUB_STATE/jailhub.sock` (0600). 소켓 파일 권한이 곧 인가다.
- 프로토콜: 줄 단위 JSON 요청/응답. `jailscale-proto`의 코덱을 재사용.
- 명령: `node list|approve|deny|remove|rename`, `name list|reassign|release`, `domain list|release`,
  `user list|remove`, `invite create|list|revoke`, `authkey create|list|revoke`,
  `admin add|remove|login-link`, `key rotate`, `setting <key> <value>`, `status`, `handoff`.
- **실행 중 바꿀 수 있는 설정**(초대 정책, 가입 방식, 두드리기 허용)은 저장소에 산다. `serve`의
  플래그는 첫 기동 때 값을 심을 뿐이고, 이후는 `/admin`이나 `jailhub setting`이 바꾼다. 재시작해도
  유지된다.

**관리 웹 `/admin`.** 승인 큐가 있는 이상 관리자가 hub 셸에 들어가야만 승인할 수 있다면
사용성 원칙 위반이다. 최소 페이지를 v1에 둔다.

- 인증: 비밀번호도 IdP도 없다. **관리자 노드의 MachineKey가 신원이다.** 관리자가 자기 노드에서
  `jailscale admin`을 치면 노드가 스트림 0으로 `AdminLink`를 요청하고, hub이 60초짜리 일회용
  URL을 돌려주면 CLI가 브라우저를 연다. 방문 시 세션 쿠키 `HttpOnly; Secure; SameSite=Lax`.
  노드가 없는 상황(첫 설치, 복구)은 hub 셸에서 `jailhub admin login-link`.
- 기능: 대기 큐 승인/거부, 노드·이름·도메인 목록과 삭제·해제, 초대 발급, auth-key 발급,
  설정(초대 정책·가입 방식·두드리기) 토글. 이것뿐이다.
- 구현: 서버 렌더링 HTML, JS 없음, CSS 인라인. 템플릿 엔진 없이 문자열 조립. 폼마다 세션에
  묶인 CSRF 토큰. 세션 12시간. (M3 구현)

### 7.7 가용성: hub은 하나다

v1의 hub은 단일 프로세스, 단일 호스트다. 주 사용처가 self-host 단일 VPS이고, 규모 면에서는 hub
하나가 수천 노드와 수만 스트림을 감당한다(바이트 복사와 서명뿐이다). 남는 것은 가용성이며,
v1은 **빠른 복구**로 답한다.

| 항목 | 목표 |
|---|---|
| hub 프로세스 재시작 | 상태 리플레이 포함 5초 이내. 노드는 1·2·4·8초 백오프로 재접속 |
| 방문자가 겪는 것 | 재시작 동안 연결 거부. 진행 중이던 스트림은 끊긴다 |
| 백업 단위 | `$JAILHUB_STATE` 디렉터리 하나. `hub.key`·`tls/`·`state.*`가 전부다 |
| 호스트 교체 | 새 호스트에 디렉터리를 복사하고 DNS를 바꾼다. 노드는 hkey와 와일드카드 키가 같으므로 아무것도 모른다 |

대기 hub(디렉터리 복제 + 낮은 TTL DNS 또는 유동 IP)은 §15. 능동-능동은 방문자가 붙은 hub과
노드가 붙은 hub이 다를 수 있어 hub 사이 전달이 필요하며, 다중 hub 설계 전체라 v2 이후다.

**무중단 교체 (hand-off, M3 구현).** hub 바이너리를 갱신할 때는 재시작 대신 **인수**한다.
`jailhub serve --takeover`로 새 프로세스를 띄우면:

1. 새 프로세스가 옛 프로세스의 IPC 소켓으로 `handoff`를 보낸다.
2. 옛 프로세스는 443 리스너·raw 포트·80·DNS·ACME를 닫고, 상태를 스냅샷한 뒤 상태 잠금을
   놓고, 모든 노드에 `Goodbye{draining}`을 보낸다. 진행 중인 방문자 스트림은 그 연결에서 계속
   흐른다(**draining 연결**). 새 방문자 스트림은 더 열지 않는다.
3. 새 프로세스가 잠금을 잡고 리플레이한 뒤 443을 연다. 그 사이(수백 ms) 새 방문자는 연결
   거부를 겪는다. `SO_REUSEADDR`라 바인드 대기는 없다.
4. 노드는 `draining`을 받으면 **즉시 새 연결**을 열고 링크를 다시 연다. 옛 연결은 열린
   스트림이 모두 끝날 때까지 남겨두었다가 닫는다. 서명 요청은 스트림을 소유한 연결로 보낸다.
5. 옛 프로세스는 draining 연결이 모두 비면(상한 60초) 종료한다. IPC 소켓 파일은 자기 것일
   때만 지운다(새 프로세스의 소켓을 지우지 않도록 inode 비교).

방문자가 겪는 것은 "새 연결이 수백 ms 거부됨"뿐이고, 진행 중이던 다운로드·WebSocket은 끊기지
않는다. 노드는 재접속 백오프 없이 바로 붙는다. 배포 스크립트는 `jailhub serve --takeover`
한 줄이다. 롤백도 같은 명령이다.

**draining 목록에서 빠지는 조건.** 노드가 4번에서 남겨둔 연결은 `onClosed` 콜백이 목록에서
제거한다. 그런데 그 콜백은 hub이 이미 닫아버린 연결에 대해서는 다시 울리지 않는다. 그런
일이 두 가지 경로로 생긴다. hub이 감시가 시작되기 전에 연결을 끊는 경우, 그리고 추가 연결이
자기 읽기 루프에서 먼저 `onClosed`에 도달해 아직 목록에 없는 자신을 지우려 드는 경우다.
둘 다 연결은 죽었는데 항목만 남아 `drainingCount()`가 영원히 0이 되지 않는다. 그래서
감시 스레드가 끝날 때 직접 제거한다.

---

## 8. 스트림 멀티플렉서 (`jailscale-proto`)

노드와 hub 사이의 Noise 채널 하나 위에 **여러 바이트 스트림**을 싣는다. 방문자 연결 하나가
스트림 하나다. v3의 DERP 프레임이 있던 자리다. yamux와 같은 수준의 프로토콜이며 500줄 안팎.

프레임: `[4B streamId][1B type][1B flags][2B len][payload]`. 프레임 하나가 Noise 메시지 하나 안에
들어가며, DATA 페이로드는 **16 KB 상한**이다. 65535까지 채우면 스트림 하나가 채널을 독점한다.
`flags`의 `DGRAM` 비트가 켜진 스트림은 DATA 프레임 하나가 데이터그램 하나다 (UDP 공개, §9.5).

| 타입 | 페이로드 | 방향 | 의미 |
|---|---|---|---|
| `OPEN` | `{linkId, sni?, visitorAddr, keyId?}` JSON | H→N | hub이 방문자 연결을 배달. https는 `sni`, raw 포트는 `linkId`가 스트림의 정체다 |
| `DATA` | 바이트 | 양방향 | 스트림 데이터 |
| `WINDOW` | `[4B delta]` | 양방향 | 흐름 제어 윈도우 증가 |
| `CLOSE` | 없음 | 양방향 | 반쪽 닫기 (FIN 상당) |
| `RST` | `[1B reason]` | 양방향 | 강제 종료 |
| `CTRL` | JSON | 양방향 | **스트림 0 전용.** §7 메시지 |
| `KEEPALIVE` | 없음 | 양방향 | **25초 주기**, 60초 무응답 시 연결 종료 |

- **흐름 제어.** 스트림당 수신 윈도우 256 KB, 연결당 합계 8 MB. 윈도우가 0이면 송신 측이
  멈춘다. 느린 방문자 하나가 다른 스트림을 막지 않게 하는 장치다. TCP 위이므로 재전송은 없다.
- **스트림 ID.** hub이 여는 스트림은 짝수, 노드가 여는 스트림은 홀수(현재는 없음. 향후 노드
  발신용). 0은 컨트롤.
- **우선순위.** writer는 스트림 0의 프레임을 먼저 내보낸다. `SignRequest`/`SignResponse`가
  방문자 데이터에 밀리면 핸드셰이크 지연이 늘어난다.
- **노드당 다중 연결.** 모든 스트림이 한 TCP+TLS 연결을 공유하면 손실 시 함께 멈추고(head-of-line)
  처리량이 TCP 흐름 하나의 상한에 걸린다. 그래서 노드는 hub에 연결을 **N개** 연다. 기본 N=1,
  `--connections 4`까지. 각 연결은 완전한 Noise 채널이며 `Hello{conn: 0..N-1}`로 번호를 밝힌다.
  hub은 같은 MachineKey의 연결들을 **묶음**으로 다룬다. 스트림 0(컨트롤)은 0번 연결에만 있고,
  방문자 스트림은 묶음 안에서 미해결 바이트가 가장 적은 연결에 배정한다. 서명 요청은 0번
  연결의 스트림 0으로 가되 `streamId`에 연결 번호를 상위 8비트로 넣어 어느 연결의 스트림인지
  hub이 안다. 0번 연결이 끊기면 묶음 전체를 끊고 노드가 다시 연다. (M3 구현. 서명 요청은
  실제로는 스트림을 소유한 연결로 보내는데, hand-off 중 draining 연결의 스트림이 0번 연결에서
  찾아지지 않는 문제를 피하기 위해서다. 검사 조건은 같다.)
- 같은 MachineKey·같은 `conn` 번호로 두 번째 연결이 오면 옛 연결을 `Goodbye{shutdown}`으로 닫고
  새 연결이 이긴다. 옛 연결의 스트림은 전부 `RST`.
- 연결 소켓에 `TCP_NODELAY`.

---

## 9. 공개 인그레스 (`jailscale-hub`)

### 9.1 SNI 라우터

hub의 443은 **하나의 `ServerSocket`**이 받는다. TLS를 열지 않은 채 ClientHello를 읽어(최대
16 KB, 5초 타임아웃) SNI를 파싱하고 분기한다. 파서는 레코드 헤더 → 핸드셰이크 → 확장 목록 →
server_name 순으로 100줄이다.

| SNI | 처리 |
|---|---|
| `hub.example.com` | hub 자신의 `SSLServerSocket`으로 넘긴다. 컨트롤 채널·`/join`·`/admin`·`/v1/*` |
| `<name>.hub.example.com`, 활성 이름 | 소유 노드의 mux에 `OPEN{sni, visitorAddr, keyId}` 스트림을 열고, 이미 읽은 ClientHello 바이트부터 그대로 넘긴다 |
| `<name>.hub.example.com`, 미배정·비활성 | hub이 와일드카드로 종단해 "그런 링크가 없습니다" 페이지. hub에 키가 있으니 가능하다 |
| 등록된 사용자 도메인 | 소유 노드로 스트림. `keyId`는 `user-domain` (hub은 그 키가 없다) |
| 그 외, SNI 없음 | 즉시 닫는다 |

이후 hub은 양방향으로 바이트만 복사한다. TLS 레코드도 HTTP도 보지 않는다. 방문자 소켓 →
스트림 `DATA`, 스트림 `DATA` → 방문자 소켓. 방문자 쪽 반쪽 닫기는 `CLOSE`, 오류는 `RST`.

**연결 한도.** 방문자 IP당 동시 연결 64, 이름당 동시 연결 1024, ClientHello 대기 5초. SYN 플러드
방어는 OS 몫이다. 루프백에서 온 연결은 IP당 한도에서 제외한다. PROXY 프로토콜 없이 로컬 프록시
뒤에 두면 모든 방문자가 한 주소로 보이기 때문인데, 그 배치에서는 `--proxy-protocol`(§9.6)이
정답이고 이 예외는 안전망이다. 리스너 backlog는 1024(OS `somaxconn`이 상한).

**hub이 보는 것.** SNI, 방문자 IP, 바이트 수, 연결 시각. 내용은 못 본다. 이것이 v3의 "hub은
내용을 못 본다"를 이 구조에서 되찾은 지점이다.

**HTTP가 아니어도 TLS+SNI면 443으로 된다.** hub도 노드도 HTTP를 파싱하지 않으므로, SNI를
보내는 TLS 클라이언트는 무엇이든 이름으로 붙는다. `psql "sslmode=require host=db.hub.example.com"`,
MQTT over TLS, gRPC가 그렇다. `jailscale open 5432`는 HTTP 앱과 똑같이 동작한다. TLS를 쓰지
않는 클라이언트만 §9.5의 raw 포트가 필요하다.

**방문자가 자기 쪽을 안 닫을 때.** 양방향 모두 반닫기이므로(§8) hub은 노드 쪽이 끝난 뒤에도
방문자가 자기 half를 닫을 때까지 기다린다. 방문자에게는 그럴 의무가 없다. 그래서 노드가 자기
쪽을 닫은 시점부터 10초를 세고, 그 안에 닫지 않으면 hub이 소켓을 닫는다. 이 시계는 노드가
끝낸 뒤에야 돌기 시작하므로 계속 열려 있어야 하는 스트림(WebSocket·SSE·긴 다운로드)은 여기에
닿지 않는다. 없으면 소켓과 그것을 읽는 스레드, 반쯤 열린 스트림이 무기한 묶인다.

### 9.2 이름

- **형식.** `<name>.hub.example.com`. `name`은 소문자·숫자·하이픈, 3~40자. `hub`·`admin`·`www`·
  `_acme-challenge` 같은 예약어 금지.
- **임의 이름.** `jailscale open 3000`은 `q7x2k` 같은 5자 임의 이름을 받는다. 같은 노드가 같은
  로컬 포트로 다시 열면 hub이 이전 이름을 돌려준다. 재시작해도 URL이 바뀌지 않는다.
- **지정 이름.** `--name myapp`. 첫 요청자의 사용자에게 귀속되고, 같은 사용자의 다른 노드도 쓸
  수 있다. 다른 사용자가 요청하면 `taken`. 관리자가 `name reassign`으로 옮긴다.
- **활성.** 노드가 `LinkOpen`을 보내고 연결이 살아 있는 동안만 라우팅된다. 노드가 끊기면
  이름은 소유자에게 남지만 방문자는 "오프라인" 페이지를 본다.
- **와일드카드라 이름 생성에 ACME가 없다.** 이름을 여는 데 걸리는 시간은 `LinkOpen` 왕복
  하나다.

### 9.3 서명 위임 — 노드가 종단하고 hub이 서명한다

노드는 hub에서 받은 와일드카드 **인증서**로 방문자와 TLS를 맺지만 **개인키가 없다.** TLS 1.3
서버 핸드셰이크에서 개인키가 하는 일은 `CertificateVerify`의 서명 한 번이다. 노드는 그 서명을
hub에 부탁한다.

```
방문자 ──ClientHello──► hub ──OPEN+bytes──► 노드 (SSLEngine)
                                                │  트랜스크립트 해시 h
                                                ├──SignRequest{streamId, keyId, ECDSA-P256-SHA256, h}──► hub
                                                │                                     검사 후 서명
                                                ◄──SignResponse{streamId, sig}────────────────────────┘
                                                │  ServerHello…CertificateVerify(sig)…Finished
방문자 ◄──────────────── hub ◄──bytes────────── 노드
```

**서명 오라클을 막는 조건.** hub은 트랜스크립트 해시만 보므로 어느 SNI의 핸드셰이크인지 알 수
없다. 조건 없이 서명하면 모든 멤버 노드가 와일드카드 전체의 서명 오라클을 갖고, 방문자의
DNS를 속일 수 있는 공격자는 남의 이름을 사칭할 수 있다. 따라서 hub은 다음을 모두 만족할 때만
서명한다.

1. `streamId`가 **이 연결에서 hub이 연 스트림**이고, 아직 열려 있다.
2. 그 스트림의 `OPEN`에 기록된 `sni`가 **이 노드에 배정된 이름**이다.
3. 그 스트림에서의 서명 횟수가 상한(4) 이내다. TLS 1.3 정상 핸드셰이크는 1회, HelloRetryRequest를
   고려해도 2회면 충분하다.
4. 노드당 서명 요청 한도 이내다. 토큰 버킷으로 한 번에 2,000회, 지속 초당 1,000회(M4 부하 테스트에서
   방문자 1,000명이 동시에 핸드셰이크하는 경우를 기준으로 정했다. 세션 재개는 서명이 없다).

트랜스크립트에는 양쪽 랜덤이 들어가므로 이 서명은 다른 연결에 재사용할 수 없다. 결과적으로
노드는 **hub이 자기에게 배달한 연결에 대해서만** 서명을 받고, 사칭할 수 있는 것은 자기 이름뿐이다.
그것은 원래 자기 것이다.

**서명만 필요하게 만들기.** 인증서를 ECDSA P-256으로 받는다 (§6.3). TLS 1.3과 TLS 1.2 ECDHE
스위트 모두 개인키 연산이 서명 하나다. RSA 키 교환(복호화 필요)은 끈다. TLS 1.3 세션 재개는
노드의 티켓 키로 처리되어 hub 왕복이 없다. 0-RTT는 끈다.

**키 회전.** `CertUpdate`는 `keyId`(인증서 지문)를 담는다. 노드는 최신 `keyId`로 새 핸드셰이크를
시작하고, `SignRequest`에 `keyId`를 넣는다. hub은 옛 키를 24시간 더 갖고 있으므로(§6.3) 갱신
직전에 시작된 핸드셰이크도 완료된다.

**지연.** 방문자의 첫 핸드셰이크마다 노드↔hub 왕복 한 번이 붙는다. Cloudflare Keyless SSL이
내는 비용과 같다. `SignRequest`는 스트림 0 우선순위로 나가고(§8), M2에서 실측한다 (§4 예산표).

### 9.4 사용자 도메인 (M3)

`jailscale open 3000 --domain myapp.com`. 사용자가 자기 도메인을 가져온다. 사용자가 원할 때만
쓰는 기능이지 미루는 기능이 아니다.

- 사용자는 `myapp.com CNAME hub.example.com`(또는 A)을 만든다.
- 노드는 `domains/<domain>.{key,pem}`이 없거나 갱신 시점이면 자기 키로 ACME HTTP-01을 먼저
  치른다. DNS가 hub을 가리키므로 CA의 `http://myapp.com/.well-known/…` 요청은 hub의 80으로 온다.
  노드가 `ChallengeSet{token, keyAuthorization}`을 올려두면(노드당 10개, 10분) hub이 그 값을
  대신 답하고, 끝나면 `ChallengeClear`. hub은 토큰과 응답 문자열만 알 뿐 키를 모른다.
- 그 다음 `LinkOpen{domain, chainPem}`. **인증서 체인이 소유 증명이다.** hub은 체인이 공개 CA로
  검증되고 SAN이 그 도메인일 때만 도메인을 노드에 귀속시킨다. 체인이 없으면 `domain-unverified`,
  이름이 다르면 `domain-cert-name-mismatch`, 검증 실패면 `domain-cert-untrusted`. hub 이름 아래의
  이름은 `bad-domain`. 같은 도메인의 유효한 인증서를 가진 다른 노드가 오면 그 노드가 이긴다
  (도메인을 실제로 통제하는 쪽이 인증서를 받을 수 있으므로).
- 이후는 순수 SNI 통과다. 인증서도 키도 노드에만 있고, hub은 그 이름의 암호문을 넘길 뿐이다.
  `SignRequest`는 없다.
- 인증서 한도는 사용자 자신의 등록 도메인 기준이라 hub 도메인의 한도와 무관하다.
- 갱신은 노드가 잔여 수명 1/3 규칙으로 스스로 한다. 노드가 오프라인이면 갱신도 멈추므로 만료
  7일 전 `jailscale status`가 경고한다.
- **hub 80 포트가 이 기능의 전제다.** 80을 열지 않은 hub은 사용자 도메인을 거부한다.
  tls-alpn-01(80 불필요, 노드가 자체 서명 챌린지 인증서 생성)은 §15.

이 절이 v3에서 "keyless로 사용자 도메인"이라 했던 것의 최종 형태다. 노드가 어차피 TLS를
종단하므로 사용자 도메인은 노드 키 + 통과로 충분하고, 서명 위임은 hub 도메인 이름에만 쓴다.

### 9.5 raw TCP / UDP 포트 공개 (M3)

TLS를 쓰지 않는 클라이언트(SSH, 게임 서버, 평문 DB, DNS, WireGuard 같은 UDP 프로토콜)는
SNI가 없어 이름으로 구분할 수 없다. 그래서 hub이 **이름 대신 포트**를 배정한다. ngrok의 tcp
모드, frp의 tcp/udp 타입과 같은 구조다.

```
$ jailscale open 22 --tcp
tcp://hub.example.com:10042  →  127.0.0.1:22
$ jailscale open 51820 --udp
udp://hub.example.com:10043  →  127.0.0.1:51820
$ jailscale open 22 --tcp --port 10022                  # 희망 포트. 비어 있으면 배정
```

- **포트 범위.** hub `--port-range 10000-10999`(기본). 이 범위를 방화벽에서 TCP와 UDP 모두
  열어야 하며, 운영자 준비 목록에 "raw 포트를 쓸 때만" 조건으로 들어간다 (§6.3). 범위 크기가
  곧 동시 raw 공개 수 상한이다. 배정된 포트는 같은 노드·같은 로컬 포트에 대해 유지된다.
- **TCP.** hub이 배정 포트에 `ServerSocket`을 연다. 방문자 연결마다 `OPEN{linkId, visitorAddr}`
  스트림을 열고 바이트를 복사한다. SNI 파싱 없음, TLS 없음.
- **E2E의 한계.** 방문자↔hub 구간은 방문자 클라이언트가 보낸 그대로이고, hub↔노드 구간은
  여전히 Noise로 암호화된다. 따라서 평문이 존재하는 곳은 **hub 프로세스 안**뿐이며, 그것도
  앱이 스스로 암호화하지 않을 때만이다. SSH·WireGuard·자체 TLS를 켠 DB는 hub이 앱의 암호문만
  보므로 사실상 E2E이고, 평문 프로토콜은 hub이 본다. 방문자 클라이언트가 협조하지 않는 한
  우리가 고칠 수 없는 한계이며 ngrok·frp도 같다. 이 점을 `open --tcp/--udp` 출력에 한 줄로 알린다.
  클라이언트가 TLS를 말할 수 있으면 §9.1의 443 경로가 E2E다.
- **UDP.** hub이 배정 포트에 `DatagramChannel`을 연다. 처음 보는 방문자 주소마다 `DGRAM` 플래그의
  스트림을 열고, 이후 그 주소의 데이터그램은 그 스트림의 DATA 프레임 하나씩으로 나른다.
  노드는 스트림마다 로컬 UDP 소켓을 하나 만들어 로컬 포트로 보내고, 응답을 같은 스트림으로
  돌려보낸다. 방문자 주소별 유휴 60초면 스트림을 닫는다. 데이터그램 크기 상한은 mux 프레임
  상한 16 KB이며 일반 UDP는 1,500B 아래라 문제없다. 순서와 손실은 TCP 위라 보존되는데, UDP
  앱이 기대하는 의미론보다 강할 뿐 약하지 않다.
- **범위 밖.** 포트 범위 밖의 포트(예: 방문자에게 `:22`로 보이게)는 지원하지 않는다. hub의 낮은
  포트는 hub 자신의 것이다.

### 9.6 TCP 프록시 뒤 배치와 PROXY 프로토콜 (M4)

이미 nginx나 HAProxy가 443을 쥔 서버에 hub을 얹는 운영자를 지원한다. 조건은 프록시가
**TLS를 열지 않고 TCP 바이트만 넘기는 것**이다.

- 참조 설정 두 벌을 배포물에 동봉한다. nginx `stream { server { listen 443; proxy_pass
  127.0.0.1:8443; proxy_protocol on; } }`와 HAProxy `mode tcp` + `send-proxy-v2`. SNI 기반으로
  hub 이름 아래만 hub으로 보내고 나머지는 기존 서비스로 보내는 `ssl_preread` 예시도 넣는다.
- hub은 `--listen 127.0.0.1:8443 --proxy-protocol`로 뜬다. `--proxy-protocol`이 켜지면 연결 첫
  바이트에서 PROXY v1/v2 헤더를 읽어 방문자 IP를 얻는다. 이 헤더는 신뢰하는 프록시에서만
  와야 하므로 `--proxy-protocol`은 `--listen`이 루프백이거나 `--trusted-proxy <cidr>`가 있을 때만
  받는다. 아니면 누구나 방문자 IP를 위조한다.
- 자가 진단(§6.3)은 프록시 뒤에서도 그대로 동작한다. 공인 이름이 결국 hub에 닿는지를 보기 때문이다.
- raw 포트(§9.5)도 같은 방식으로 프록시를 거칠 수 있지만 참조 설정은 443만 다룬다.
- (M4 구현) 파서는 v1 텍스트와 v2 바이너리(IPv4·IPv6·LOCAL) 모두 받는다. v1의 주소는 **리터럴만**
  받는다. 호스트명을 허용하면 accept 경로에서 DNS 조회가 일어나 공격자가 hub을 멈출 수 있다
  (퍼징이 찾았다). `--proxy-protocol`이 켜진 hub은 헤더 없는 연결을 거부하므로 노드의 컨트롤
  연결도 프록시를 지나야 한다. 참조 파일은 `deploy/nginx-stream.conf`, `deploy/haproxy.cfg`.

---

## 10. 노드 (`jailscale-node`)

### 10.1 공개 링크 UX

```bash
$ jailscale open 3000
https://q7x2k.hub.example.com  →  127.0.0.1:3000        (링크가 클립보드에 복사됨)

$ jailscale open 3000 --name myapp                     # 지정 이름
$ jailscale open 3000 --gate                           # 방문자 게이트. 방문 링크가 함께 출력됨
$ jailscale open 3000 --domain myapp.com               # 사용자 도메인 (§9.4)
$ jailscale open 22 --tcp                              # raw TCP. hub 포트가 배정된다 (§9.5)
$ jailscale open 51820 --udp                           # raw UDP
$ jailscale open 8080 --host 192.168.1.20              # 같은 LAN의 다른 기기도 내놓을 수 있다
$ jailscale ls
$ jailscale close q7x2k
```

열린 링크는 데몬이 기억한다. 재부팅 후에도 같은 이름·포트로 다시 열린다. 포그라운드 모드
`jailscale open 3000 --fg`는 프로세스가 끝나면 닫는다.

### 10.2 TLS 종단과 원격 서명

방문자 스트림(§8)은 소켓이 아니라 바이트 스트림이므로 `SSLSocket`을 얹을 수 없다. `SSLEngine`을
직접 돌린다. 스트림 → `unwrap` → 평문 → 로컬 소켓, 로컬 소켓 → `wrap` → 스트림. 200줄 안팎.

- `SSLContext`는 hub이 `CertUpdate`로 준 인증서 체인과 **불투명한 `PrivateKey`**로 구성한다.
  이 키 객체는 바이트를 갖고 있지 않고 `keyId`만 안다.
- 자체 JCE `Provider`가 `Signature.SHA256withECDSA`를 이 불투명 키에 대해 제공한다. JSSE는
  키 타입에 맞는 공급자를 고르는 지연 선택을 하므로(PKCS#11 키가 쓰는 경로) 우리 공급자가
  선택된다. 구현은 `engineSign()`에서 스트림 0으로 `SignRequest`를 보내고 응답을 기다린다.
  virtual thread 위라 블로킹해도 된다. 등록은 `Provider.Service` 서브클래스의 `newInstance`
  재정의로 하며 리플렉션이 없다.
- `SSLParameters`: 프로토콜 TLS 1.3 + 1.2, ECDHE 스위트만, ALPN `http/1.1`만, 0-RTT 없음.
  h2를 협상하면 로컬 앱이 h1일 때 깨진다.
- 세션 티켓 키는 노드가 생성해 메모리에만 둔다. 재개 핸드셰이크는 hub을 거치지 않는다.
- 사용자 도메인 스트림(`keyId = user-domain`)은 `domains/<domain>.key`의 진짜 키로 종단한다.

### 10.3 릴레이

TLS를 벗긴 뒤 노드는 **바이트를 복사할 뿐이다.** 방문자가 보낸 평문 → `127.0.0.1:<port>`,
로컬 응답 → 방문자. HTTP/1.1 keep-alive, chunked, WebSocket Upgrade, SSE가 전부 그대로 통과한다.
로컬 앱이 처리하기 때문이다. 방문자 IP를 로컬 앱에 알리고 싶으면 `open --proxy-protocol`로 첫 줄에
PROXY v1 헤더를 붙인다(HAProxy 형식, 앱이 지원할 때만). hub이 `visitorAddr`·`visitorPort`를 스트림
메타에 실어 보내고, 목적지 주소로는 로컬 대상을 적는다. raw TCP 링크도 같다. (M4 구현)

로컬 연결이 거부·리셋되면(작은 listen backlog에 방문자가 몰릴 때 macOS 기본 128에서 실제로 난다)
50 ms부터 두 배씩 다섯 번 재시도한 뒤에야 502를 낸다.

로컬 연결 실패는 방문자에게 502 HTML 한 장을 돌려주고 닫는다. 이것과 게이트가 노드가 HTTP를
**쓰는** 유일한 두 지점이며, https 링크에서만 그렇다. raw TCP 스트림은 TLS 없이 바이트만
복사하고, raw UDP 스트림(`DGRAM`)은 DATA 프레임 하나를 로컬 UDP 소켓의 데이터그램 하나로
보낸다 (§9.5).

### 10.4 방문자 게이트 (`--gate`)

공개하고 싶지 않은 링크는 방문 링크로 잠근다. 초대와 같은 역량 모델이다.

```
$ jailscale open 3000 --gate
https://q7x2k.hub.example.com                    (게이트 켜짐)
방문 링크: https://q7x2k.hub.example.com/?jail=8Hq…   (24시간, 클립보드에 복사됨)
$ jailscale gate q7x2k --new-link --ttl 7d
```

- 노드가 TLS를 벗긴 직후 **연결의 첫 요청 헤더만** 읽는다(요청 줄 + 헤더, 최대 16 KB).
  `Cookie: jail=<token>`이 유효하면 그 연결을 통째로 통과시킨다. 같은 TCP 연결은 같은 클라이언트다.
- `?jail=<token>` 쿼리가 유효하면 `Set-Cookie: jail=…; Secure; HttpOnly; SameSite=Lax` + 쿼리를
  뺀 경로로 302, 그리고 닫는다.
- 둘 다 없으면 403 HTML 한 장을 돌려주고 닫는다.
- 토큰은 128비트, 노드에는 해시만. hub은 게이트를 모른다. 암호문만 보기 때문이다. 게이트가
  노드에 있는 것은 E2E와 일관된 자리다.
- 본문은 읽지 않으므로 HTTP 파싱은 헤더 경계(`\r\n\r\n`)까지다.

### 10.5 데몬과 CLI

`jailscale`은 하나의 바이너리지만 두 역할이다. `jailscale daemon`(또는 서비스 등록)이 상주하고,
나머지 서브커맨드는 데몬에 **로컬 IPC**로 요청한다.

- 전송: AF_UNIX 소켓. `$XDG_RUNTIME_DIR/jailscale.sock`, 없으면
  `~/.config/jailscale/jailscale.sock` (0600). Windows도 AF_UNIX
  (`%LOCALAPPDATA%\jailscale\jailscale.sock`, 현재 사용자 ACL).
- 프로토콜: 줄 단위 JSON 요청/응답 + 스트림 응답(가입 진행, 링크 로그). hub 관리 IPC와 같은 코덱.
- 명령: `up`, `down`, `status`, `open`, `close`, `ls`, `gate`, `invite`, `admin`, `netcheck`, `leave`,
  `service install|uninstall|status`.
- **서비스 등록**(M4 구현)은 OS가 이미 가진 것만 쓴다. macOS는 `~/Library/LaunchAgents`의 launchd
  에이전트(`KeepAlive`), Linux는 `systemctl --user` 유닛(root면 시스템 유닛), Windows는 로그온 시
  실행되는 예약 작업(`schtasks /SC ONLOGON`). 실행 명령은 자기 자신의 경로이며, fallback JAR로
  돌고 있으면 `java -jar <jar>`가 된다. 별도 서비스 래퍼는 없다.
- `jailscale up`은 데몬이 없으면 데몬을 먼저 띄운다. `jailscale open`은 가입이 안 되어 있으면
  초대 링크를 묻는다.
- 콜드 스타트 50ms 목표는 이 CLI 왕복에 대한 것이다.

### 10.6 노드가 하지 않는 것

v3의 노드가 하던 일 대부분이 없다. WireGuard도, userspace TCP도, STUN도, SOCKS5도, MagicDNS도
없다. 노드는 아웃바운드 443 하나로 hub에 붙어 스트림을 받고, TLS를 벗겨 로컬로 넘긴다.
인바운드 포트를 열지 않고 UDP를 쓰지 않으며 root가 필요 없다. 이것이 노드 RSS 목표를 30MB에서
20MB로 내릴 수 있는 이유다.

---

## 11. 가입 — 초대와 승인

IdP를 두지 않는다. 가입 권한은 **역량(capability)** 으로 전달한다. 초대 링크, 짧은 코드,
auth-key는 모두 "소지가 곧 권한"인 비밀값이고, hub은 그 값과 함께 온 MachineKey를 가입시킨다.
가입은 곧 **발행 권한**이다. 가입한 노드는 이름을 열 수 있고, 방문자는 가입하지 않는다.

### 11.1 IdP를 빼는 이유

- IdP가 주는 것은 "이 사람이 누구인가"뿐이다. "발행해도 되는가"는 주지 않아서 초대·승인 큐를
  따로 만들어야 한다. 결국 IdP는 초대받은 사람에게 이름표를 붙이는 장치다.
- 비용은 크다. hub 운영자의 앱 등록, 1,000줄 규모의 보안 민감 코드, IdP 계정이 없는 협업자 배제.
- 초대 링크에 이름을 실으면 이름표 문제가 그대로 풀린다. Tailscale의 auth-key, headscale의
  pre-auth key, Syncthing의 기기 승인이 모두 이 모델이며 IdP가 없다.

**잃는 것.** 외부에서 검증된 신원이 없으므로 링크가 새면 다른 사람이 그 이름으로 들어온다.
대응은 1회용·짧은 TTL 기본값과 관리자 목록에서의 삭제다. 수십 명 이상 조직에서는 IdP가 다시
필요할 수 있으므로 §15에 OIDC 연동 슬롯을 남긴다.

### 11.2 초대 발급 — 어디서든 한 줄

초대는 **관리자만의 것이 아니다.** 기본 정책은 멤버 누구나 자기 노드에서 발급할 수 있다.
발급자는 기록되고, 관리자는 `--invite-policy admins`로 좁힐 수 있다.

```
$ jailscale invite
초대를 만들었습니다 (1회, 24시간).
  링크:  https://hub.example.com/join/9f1cQ2…       ← 클립보드에 복사됨
  코드:  7F3K-92QX                                  ← 전화로 불러줄 때 (10분)

$ jailscale invite --user bob --uses 3 --ttl 7d      # 이름 고정, bob의 기기 3대
$ jailscale invite --self                            # 내 기기 하나 더
$ jailhub invite create ...                          # hub 셸에서도 같은 옵션
```

- **링크**는 128비트 토큰(base64url 22자). 기본 1회 · 24시간.
- **코드**는 같은 초대의 별칭이다. Crockford base32 8자(40비트), **10분 · 1회**로 짧게 두고,
  hub은 IP당 분당 10회로 시도를 제한하며 실패가 쌓이면 코드를 폐기한다.
- `--user`가 없으면 가입자가 이름을 적는다. `jailscale up`이 OS 사용자명을 기본값으로 묻는다.
- 클립보드 복사는 `pbcopy` / `xclip` / `clip.exe`를 `ProcessBuilder`로 부른다. 없으면 건너뛴다.
- 발급 요청은 IPC → 스트림 0 `InviteCreate` → hub. hub에는 토큰의 해시만 남는다.

### 11.3 가입 흐름

```
$ jailscale up --invite https://hub.example.com/join/9f1cQ2…
 │        (또는 --hub hub.example.com --code 7F3K-92QX, 또는 --auth-key jk_…)
 ├─1. 링크에서 hub 호스트명을 뽑고 /v1/key로 hkey를 고정 (§6.2)
 ├─2. Noise 채널 개시, Hello로 버전 협상 (§7)
 ├─3. "hub.example.com 에 가입합니다. 이름 [wq]:"  ← 초대에 이름이 없을 때만 묻는다
 ├─4. RegisterRequest{ hostname, os, invite }
 ├─5. hub: 토큰 해시 대조 · 만료·잔여 횟수 확인 · 사용 횟수 차감 · 노드 ID 부여
 └─6. RegisterResponse{ approved } → CertUpdate. 이제 jailscale open 을 칠 수 있다
```

브라우저가 열리지 않는다. 헤드리스 서버에서도 같은 명령이다. `/join/<token>`을 브라우저로
열면 사용 횟수를 소모하지 않고 CLI 설치 안내와 복사용 명령만 보여준다.

**피싱.** 공격자가 자기 hub의 초대 링크를 뿌려 피해자를 엉뚱한 hub에 가입시킬 수 있다. CLI는
3단계에서 어느 hub인지 출력하고 확인을 받는다. 가입해도 피해자의 로컬 서비스는 피해자가
`open`을 치기 전까지 아무것도 노출되지 않는다.

### 11.4 두드리기와 승인 큐

초대가 없어도 hub 호스트명만 알면 문을 두드릴 수 있다.

```
$ jailscale up --hub hub.example.com
관리자 승인을 기다리는 중… (호스트명 wq-macbook, mkey:0J3B…)
```

hub은 `pending` 큐에 MachineKey·호스트명·OS·출발 IP만 기록한다. 관리자가 `/admin`이나
`jailhub node approve 0J3B… --user wq`로 승인하면 열려 있는 스트림 0으로 즉시 완료가 push된다.
두드리기는 무인증이므로 IP당 대기 항목 수를 제한하고, 큐는 24시간 뒤 비운다. 관리자가
두드리기를 원치 않으면 `--knock off`.

**`--registration open`.** 개인 hub이나 소규모 팀처럼 게이트가 과한 곳을 위한 옵션이다. 켜면
두드린 노드가 **즉시 승인**된다. 초대 없이 `jailscale up --hub hub.example.com`만으로 가입이
끝나고, 이름은 가입자가 적는다. 기본값은 여전히 초대이며, 켤 때 콘솔에 위험을 명시한다.
호스트명을 아는 누구나 `*.hub.example.com` 아래 이름을 열 수 있게 되므로 §12.4의 남용 대응이
운영자 몫이 된다. 웹 가입 폼을 두지 않는 이유는 그것이 이 옵션과 같은 것을 더 많은 코드로 하기
때문이다. IP당 가입 수 제한(기본 시간당 5)은 이 모드에서도 적용된다.

### 11.5 auth-key와 최초 부트스트랩

**auth-key**는 무인 등록용 초대다. CI·컨테이너·서버가 사람 없이 가입한다.

```
jailhub authkey create --owner alice                  # alice의 노드
jailhub authkey create --tag ci --uses 20 --ttl 7d    # 태그 노드. 사람 소유자 없음
jailscale up --hub hub.example.com --auth-key jk_…
```

`jk_` 프리픽스 + 128비트, hub에는 해시만. 태그 노드의 이름은 태그에 귀속된다.

**최초 부트스트랩.** `jailhub serve`는 상태 디렉터리에 관리자가 없으면 콘솔에 첫 초대 링크를
찍는다. 그 링크로 가입한 첫 노드의 사용자가 관리자다. 관리자 추가는 `jailhub admin add <user>`
또는 `/admin`. 관리자 노드를 모두 잃으면 hub 셸에서 `jailhub admin login-link`로 복구한다.
셸 접근이 곧 최상위 권한이다.

**노드 수명.** 기본 만료 없음. 관리자 폐기(`node remove`)와 선택적 `--node-ttl`을 둔다.

### 11.6 나중에 IdP를 붙인다면

요구가 관측되면 `RegisterRequest`에 `idToken` 필드를 추가하고 hub에 OIDC 검증기를 넣는다.
초대·코드·auth-key 경로는 그대로 두고, IdP는 "이름을 외부에서 검증한 초대"의 한 형태가 된다.

---

## 12. 보안 모델

네 축이 서로 직교하며, 어느 하나가 다른 하나를 보증하지 않는다.

| 축 | 질문 | 우리의 답 |
|---|---|---|
| **전송 보호** | 방문자와 노드 사이를 누가 읽나 | hub 포함 아무도. hub은 SNI·IP·바이트 수만 본다 (§9.1) |
| **발행 권한** | 누가 이름을 열 수 있나 | 초대·auth-key·승인으로 가입한 노드만. **개방 가입 없음** |
| **방문 권한** | 누가 공개 링크에 들어오나 | 기본 공개. `--gate`면 방문 링크 소지자만 (§10.4) |
| **이름 신원** | "`myapp.hub.example.com` = alice의 노드"를 누가 보증하나 | **hub.** 라우팅 표와 와일드카드 키를 hub이 쥔다 (§12.3) |

### 12.1 서명 위임의 경계

와일드카드 개인키는 hub에만 있다. 노드는 hub이 자기에게 배달한 스트림에 대해서만, 그 스트림의
SNI가 자기 이름일 때만 서명을 받는다 (§9.3의 4조건). 따라서:

- 멤버 노드가 침해되어도 공격자가 얻는 것은 **그 노드의 이름**에 대한 사칭뿐이다. 그것은 원래
  그 노드의 것이다.
- 컨트롤 채널이 Noise로 hub 키에 고정되어 있으므로, TLS를 뚫는 MITM 프록시도 서명 요청을
  가로채거나 위조하지 못한다 (§6.1).
- hub은 서명 요청을 스트림·이름·횟수·속도로 검사하고 거부를 로그에 남긴다. 거부가 반복되는
  노드는 자동으로 연결을 끊고 관리자에게 표시한다.

### 12.2 노드는 기본적으로 아무것도 노출하지 않는다

가입만으로는 노드의 어떤 포트도 인터넷에 열리지 않는다. `jailscale open <port>`를 친 포트만,
그 명령을 친 동안만 열린다. TUN이 없으니 OS 라우팅으로 새는 경로도 없다. 방문자가 닿을 수
있는 것은 노드가 명시한 `host:port` 하나이며, 노드의 다른 서비스나 LAN은 보이지 않는다.

### 12.3 hub은 신뢰 대상이다

정직하게 적어둔다. hub이 침해되면:

| hub이 할 수 없는 것 | hub이 할 수 있는 것 |
|---|---|
| 정상 노드로 가는 방문자 트래픽 읽기 (노드가 종단한다) | **이름을 공격자 노드로 재배정**하고 와일드카드 키로 서명 → 그 이름의 방문자를 통째로 가로챈다 |
| 노드의 MachineKey·사용자 도메인 키 획득 (hub에 없다) | 임의 노드를 가입시키기, 초대를 마음대로 발급 |
| 노드의 로컬 서비스 중 공개하지 않은 것 접근 | 누가 언제 어느 이름에 얼마나 접속했는지 보기 |

v3의 메시와 달리 이 제품에서 hub은 **와일드카드 키를 쥔 TLS 권위**이기도 하다. hub 침해는 hub
도메인 아래 모든 이름의 사칭이다. 사용자 도메인(§9.4)은 예외다. 키가 노드에 있어 hub이 할 수
있는 것은 라우팅을 끊는 것뿐이다. self-host라 "hub 운영자 = 조직"인 위협 모델이 대부분의
배포에 맞고, 그 이상이 필요한 이름은 사용자 도메인으로 간다.

### 12.4 남용

공개 링크는 피싱 페이지 호스팅에 쓰일 수 있다. hub 운영자가 이름을 `name disable`로 끄고
노드를 제거할 수 있으며, 임의 이름은 5자라 추측이 어렵고 지정 이름은 가입자에게만 있다. 이름당
연결 한도(§9.1)와 노드당 이름 수 상한(기본 20)을 둔다. 그 이상의 남용 대응은 운영자 몫이다.

**`/admin` 세션.** 로그인 링크는 일회용 60초, 세션 쿠키는 12시간이며 모든 POST에 CSRF 토큰을
요구한다. 여기에 더해 **요청마다 관리자 여부를 다시 확인한다.** 링크 발급 시점에만 보면
`admin remove`가 12시간 동안 효력이 없다. IPC 소켓으로 발급된 셸 링크는 소켓 권한이 인가이므로
(§7.6) 이 확인에서 면제된다. 쿠키 이름에 `__Host-` 접두사를 쓴다. 이 접두사는 `Domain` 속성을
금지하므로, hub 이름의 형제 서브도메인(`*.<hub>`)을 통제하는 노드가 관리 쿠키를 심을 수 없다.
로그아웃은 세션을 즉시 지운다. 만료된 로그인 토큰과 세션은 요청마다 정리한다.

**기타.** auth-key·초대 토큰·코드·게이트 토큰·관리 로그인 URL은 로그에 남기지 않는다.

**IP별 레이트리밋.** 인증되지 않은 호출자가 hub에 시킬 수 있는 일에는 토큰 버킷을 둔다
(`RateLimiter`).

| 대상 | 버스트 | 지속 | 초과 시 |
|---|---|---|---|
| `/v1/noise` 핸드셰이크 | 30 | 초당 1 | HTTP 429, Upgrade 거부 |
| 자격 증명 제시 (초대 토큰·코드·auth-key) | 20 | 초당 0.2 (분당 12) | `rejected{reason: rate-limited}` |
| 두드리기 대기열 | IP당 5건 (개수 상한) | — | `rejected{reason: too-many-pending}` |

이미 등록된 노드의 재접속은 자격 증명 검사에 닿기 전에 반환되므로 버킷을 건드리지 않는다.
버스트를 넉넉히 잡은 것은 노드가 연결을 최대 4개 열고(§8) NAT 뒤에 여러 노드가 있을 수 있기
때문이다. 남용을 막는 것은 지속 속도 쪽이다.

주소를 바꿔가며 버킷 수를 불리는 공격을 막기 위해, 추적하는 키가 10,000개를 넘으면 가득 찬
버킷을 버린다. 가득 찬 버킷은 없던 것과 구별되지 않으므로 잃는 정보가 없다.

**프록시 뒤의 주소.** 위 한도와 두드리기 대기열, 세션 로그는 `SniRouter`가 PROXY 헤더에서 얻은
주소를 쓴다. 그전에는 `NodeSession`이 소켓에서 직접 읽어, TCP 프록시 뒤(§9.6)에서는 모든 노드가
프록시 주소 하나로 보였다.

---

## 13. 스레딩 모델

패킷 핫패스가 사라졌으므로 platform thread를 고집할 이유가 없다. 전부 virtual thread다.

| 역할 | 스레드 |
|---|---|
| hub 443 accept | platform 1 |
| hub 방문자 연결 (SNI 파싱 → 스트림 복사) | 연결당 virtual thread 2 (양방향) |
| hub 노드 연결 (mux reader / writer) | 노드당 virtual thread 2. writer는 스트림 0 우선 |
| hub 자기 HTTP · ACME · DNS 응답기 | 요청당 virtual thread. DNS는 platform 1 |
| 노드 mux reader / writer | virtual thread 2 |
| 노드 방문자 스트림 (SSLEngine + 로컬 소켓) | 스트림당 virtual thread 2 |
| 노드 원격 서명 | 호출 스레드에서 블로킹 (virtual thread라 비용 없음) |
| 로컬 IPC | 요청당 virtual thread |

버퍼는 스트림당 16 KB 두 개(양방향)를 풀에서 빌린다. 방문자 1,000명이면 32 MB이며, hub의
연결당 합계 윈도우 8 MB(§8)가 노드 쪽 상한을 겸한다.

---

## 14. 마일스톤

| # | 범위 | 완료 기준 |
|---|---|---|
| **M0** ✅ | 프로젝트 골격 · Maven wrapper · GraalVM native 빌드 파이프라인 · `jailscale-crypto`(BLAKE2s·HKDF·X25519·ChaCha·Noise IK) | RFC 7693/7748/8439 벡터와 noise-c IK 벡터 통과. `./native.sh`로 node·hub 바이너리 생성. 기준선: 4.9 MiB, RSS 8.4 MB, 콜드 스타트 5 ms (자리표시자 main) |
| **M1** ✅ | 컨트롤 채널 · 자체 HTTP/1.1 · hkey 부트스트랩·회전 · 버전 협상 · mux(스트림 0만) · 초대·코드·auth-key·두드리기 · **로컬 IPC (노드·hub)** · 파일 저장소 · `./measure.sh` | `jailscale invite`로 만든 링크로 다른 기기가 `jailscale up --invite`만으로 가입한다(loopback e2e 테스트 + native 프로세스로 확인). 키 회전 후 노드가 끊기지 않는다. 실측(arm64 macOS): 바이너리 24 MiB, **노드 아이들 RSS 23.8 MB(목표 20)**, hub 24.2 MB, CLI 콜드 스타트 6 ms. 인증서는 M2의 ACME 전까지 `--tls-cert/--tls-key` |
| **M2** ✅ | **와일드카드 ACME + hub DNS-01 응답기** · SNI 라우터 · mux 데이터 스트림 · 노드 `SSLEngine` 종단 · **원격 서명 Provider와 4조건 검사** · 릴레이 | `jailscale open 3007 --name demo` 후 `curl`이 hub→노드를 거쳐 로컬 앱을 받는다(native 프로세스로 확인). 서명 오라클 테스트 통과. ACME는 테스트 CA(mock)로 dns-01·CSR·발급·재시작 재사용까지 통과. 실측(loopback, arm64): 방문자 전체 핸드셰이크 2.3 ms(hub 서명 왕복 포함), 노드 RSS 26.6 MB, hub 26.2 MB. **남은 것**: 실제 도메인에서 Let's Encrypt 스테이징 발급 확인, 노드당 다중 연결(§8)은 M3로 이월 |
| **M3** ✅ | 방문자 게이트 · WebSocket/SSE 통과 검증 · 이름 관리(지정·재배정·오프라인 페이지) · `/admin` · 사용자 도메인(HTTP-01 중계) · **raw TCP/UDP 포트 공개** · 노드당 다중 연결(§8, M2에서 이월) · **hub 무중단 교체(§7.7)** | 게이트 링크 없이는 403, 방문 링크로 302+쿠키. Upgrade 에코 앱이 그대로 통과. `/admin`은 관리자 노드의 `jailscale admin` 일회용 링크로 로그인하고 승인·초대·설정을 바꾼다(설정은 저장소에 있어 재시작 후에도 유지). `--domain`은 노드가 hub을 통해 http-01을 치르고 자기 키로 종단한다(mock CA, 재시작 시 인증서 재사용). `open --tcp`는 200 KB 에코 왕복, `--udp`는 주소별 DGRAM 스트림 왕복. `--connections 2`로 스트림이 두 연결에 나뉜다. `serve --takeover`로 진행 중 스트림이 끊기지 않는다. 테스트 84개. native 프로세스로 raw tcp·https 이름·port-80 리다이렉트·admin 링크 확인. 실측(arm64 macOS): 바이너리 27.2/27.3 MiB(M2 24; 노드에 `java.net.http`가 들어옴, §15), 노드 아이들 RSS 24.8 MB, hub 25.1 MB, CLI 콜드 스타트 6.1 ms. **남은 것**: 실제 Let's Encrypt 스테이징(hub 와일드카드·노드 사용자 도메인 모두), 브라우저 3종 확인 |
| **M4** ✅ | 릴리스 패키징 (5개 플랫폼 + fallback JAR) · 서비스 등록(systemd/launchd/Windows) · 참조 systemd 유닛 · Dockerfile · **nginx stream / HAProxy 참조 설정 + PROXY 프로토콜** · 퍼징·부하 · 예산 게이트 확정 · ACME 전송을 자체 HTTP 클라이언트로 교체(`java.net.http` 제거) | `.github/workflows/release.yml`이 태그마다 linux/darwin × amd64/arm64 + windows-amd64 native와 fallback JAR(`target/jailscale.jar`, `jailhub.jar`)을 릴리스에 붙인다. `deploy/`에 systemd 유닛(reload = takeover)·Dockerfile(distroless)·nginx stream·HAProxy·Homebrew formula. `jailscale service install`. PROXY v1/v2 e2e 테스트에서 방문자 IP가 hub 한도·로그·로컬 앱(`open --proxy-protocol`)까지 정확히 전달된다. 퍼징(SNI·HTTP·mux·JSON·코덱·PROXY·DNS, 각 1만~2만 케이스)이 PROXY v1 호스트명 DNS 조회 문제를 찾았고, 부하 테스트(1,000 동시 방문자)가 다중 연결 스트림 id 충돌과 서명 한도(50/s) 문제를 찾았다. 실측(arm64 macOS, native, `LOAD=1000 ./measure.sh --check`): 바이너리 24.9/25.2 MiB, 아이들 RSS hub 24.6 / 노드 24.4 MB, 방문자 1,000명 동시 접속 1,000/1,000 성공 0.5초, 직후 RSS hub 75.5 / 노드 102.8 MB(방문자당 약 50/80 KB, TLS 세션 버퍼), CLI 6.3 ms. 게이트 통과. **남은 것**: 실제 Let's Encrypt 스테이징, 브라우저 3종, Windows·Linux에서 `service install` 실기 확인, 태그 릴리스 1회 실행 |

**테스트 전략 (마일스톤 공통)**

- 파서(JSON, HTTP/1.1 요청·응답, SNI, mux 프레임, DNS 질의)는 퍼징 대상이다. hub의 SNI 파서와
  DNS 응답기는 인터넷에 직접 노출되므로 M2에서 퍼징을 끝낸다.
- 서명 위임은 적대적 테스트를 둔다. 남의 스트림 ID, 닫힌 스트림, 배정되지 않은 SNI, 횟수·속도
  초과가 전부 거부되어야 한다.
- TLS 종단은 브라우저 3종(Chrome·Safari·Firefox)과 `curl`로 확인한다. 세션 재개가 hub 왕복 없이
  되는지 로그로 본다.
- M2 이후 매 마일스톤 종료 시 §12의 표를 기준으로 위협 모델 재검토를 한 번 한다.

---

## 15. 미해결 / 추후 결정

- **ACME tls-alpn-01** — 사용자 도메인에서 hub 80 포트를 없애기 위해. 노드가 자체 서명 챌린지
  인증서를 DER로 만들어야 한다. 요구가 있으면.
- **대기 hub** — `$JAILHUB_STATE`를 복제해 둔 두 번째 호스트 + 낮은 TTL DNS 또는 유동 IP.
  복제 도구는 rsync/litestream 류의 외부 도구로 충분한지, 내장 복제가 필요한지 요구를 보고 결정.
- **IdP 연동 (OIDC)** — 수십 명 이상 조직에서. `RegisterRequest`에 `idToken` 필드 하나 (§11.6).
- **메시 데이터 평면 복귀** — v3의 WireGuard·netstack·NAT 트래버설. 컨트롤 평면이 같으므로 mux
  옆에 두 번째 데이터 평면으로 얹는 형태가 된다. 요구가 있으면 `DESIGN-v3-mesh.md`를 기준으로 재개.
- **Windows 서비스** — CLI 브라우저 열기(`rundll32`), 파일 ACL, 서비스 등록 분기. M4.
- **raw 포트의 TLS 래핑** — `open 22 --tcp --tls`처럼 hub 포트에서도 노드 종단 TLS를 제공해
  hub이 내용을 못 보게 하는 옵션. 방문자 클라이언트가 TLS를 말할 수 있을 때만 의미가 있다.
- **방문자 핸드셰이크 지연 최적화** — 실측이 나쁘면 노드가 `ServerHello`까지의 트랜스크립트를
  미리 계산해 `SignRequest`를 더 일찍 보내는 등의 파이프라이닝. M2 실측 후.
- **`--no-tls` 컨트롤 채널** — 공개 443이 어차피 TLS라 의미가 줄었다. 보류.
- **부하 중 RSS** — 방문자 1,000명 동시에 노드 102.8 MB, hub 75.5 MB(M4 실측). 방문자당 노드 약 80 KB는
  JSSE `SSLEngine` 버퍼(패킷·앱 버퍼 각 16 KB 남짓)와 mux 스트림 버퍼다. 줄이려면 버퍼 풀링과
  스트림당 윈도우 축소(§8의 256 KB → 64 KB)가 후보. 부하가 빠진 뒤 RSS가 돌아오지 않는 것은
  Serial GC가 힙을 반납하지 않기 때문이며 `-R:MaxHeapSize`와 함께 볼 것.
- **노드 RSS 20 MB 회복** — M1 실측 23.8 MB, M2 실측 26.6 MB(JSSE 서버 측 + 원격 서명 Provider 추가). 대부분 JSSE·JCE의 이미지 힙이다. 후보는
  `-R:MaxHeapSize`로 힙 상한 고정, 빌드 시 초기화 화이트리스트 확대, 사용하지 않는 TLS 스위트·
  프로토콜 제거. M2에서 TLS 종단이 추가된 뒤 다시 재고 그때 결정.
- **ACME 클라이언트의 전송 계층** — M3의 사용자 도메인으로 노드도 `AcmeClient`를 쓰는데, 이 클라이언트는
  `java.net.http`를 썼고 바이너리가 24 → 27.3 MiB로 늘었다. **M4에서 해결**: §6.1의 자체 HTTP/1.1
  클라이언트에 chunked 디코딩을 붙여(`HttpCall`) 교체했고 바이너리는 25 MiB로 돌아왔다.
- **사용자 도메인 소유 증명** — 현재는 "그 이름으로 검증되는 공개 CA 인증서 체인"이 증명이다. 이는
  hub이 키를 갖지 않으면서도 남의 도메인을 자기 노드로 끌어가는 것을 막는다. hub 셸의 `domain release`로
  관리자가 회수할 수 있다. DNS가 hub을 가리키는지의 사전 검사(친절한 오류)는 추후.
