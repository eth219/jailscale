# jailscale 설계서 (v3, 메시 VPN 방향 — 보관용)

> Java 25 LTS + GraalVM Native Image로 만드는 경량 Tailscale.
> coordinator와 DERP 릴레이를 한 노드로 통합하고, IdP 없이 초대 링크로 가입하며,
> WireGuard 기반 userspace 네트워크 스택으로 root/TUN 없이 모든 플랫폼에서 동작한다.

문서 버전: v3 (2026-09-10)

**v3 변경 요약**

- **카카오 OAuth 제거.** IdP는 신원만 주고 멤버십은 주지 않았는데, hub 운영자 준비의 4/6과
  §11 전체를 차지했다. 가입은 **초대 링크·짧은 코드·auth-key·두드리기+승인**의 역량 모델로
  통일한다 (§11). `/admin` 로그인은 관리자 노드의 MachineKey로 한다 (§7.6).
- **초대 발급을 어디서든 한 줄로.** 관리자뿐 아니라 멤버도 자기 노드에서 `jailscale invite`로
  발급하고(기본 정책, 관리자가 끌 수 있음), 링크는 클립보드에 복사되며, 전화로 불러줄 수 있는
  짧은 코드도 함께 나온다 (§11.2).
- §7.1의 TLS 유지 논거를 OAuth 콜백이 아니라 hkey 부트스트랩·브라우저 경로·방화벽 통과로
  다시 썼다. OAuth가 사라진 결과로 `--no-tls` 모드가 성립하므로 §15에 후보로 둔다.
- NodeKey 만료는 기본 없음. 관리자 폐기로 대체 (§5, §15).

**v2 변경 요약** (v1 리뷰 반영)

- 컨트롤 채널의 HTTP 서버/클라이언트를 **자체 최소 HTTP/1.1 구현**으로 변경. JDK HTTP
  서버/클라이언트가 Upgrade 후 raw 스트림을 내주지 않아 §4 규율과 충돌했다. WebSocket도
  검토했으나 채택하지 않았다 (§7.1).
- **Caddy 제거.** hub가 TLS를 직접 종단하고 **내장 ACME HTTP-01**로 인증서를 받는다.
  v1의 "내장 ACME 안 만든다" 결정을 뒤집었다 (§7.1.2).
- 데이터 평면 폴백 경로 정리: 직접 UDP → hub TCP 릴레이(DERP). **hub UDP 릴레이**는 M4
  실측 후 결정 (§9, §15).
- 범용성 점검에서 나온 수정: 브라우저 열기에 AWT 금지, Windows IPC는 명명된 파이프 대신
  AF_UNIX, 모바일은 비목표로 명시, `ssh` 경로용 ProxyCommand와 HTTP CONNECT 프록시 추가 (§4, §10).
- **로컬 IPC** 추가. 노드 CLI ↔ 데몬, `jailhub` 관리 CLI ↔ 서버 (§7.6, §10.1).
- **프로토콜 버전 협상** 추가 (`Hello` 메시지, Noise 프롤로그) (§7.2).
- **hub 키 회전** 절차 추가. `expires`와 하드 실패의 모순 해소 (§7.1.1).
- DERP 아웃바운드를 **우선순위 큐**로 분리해 컨트롤 프레임이 드롭되지 않게 함 (§8).
- §6과 §13의 암복호 스레딩 모순 해소. 버퍼 풀은 힙 배열 기반으로 (§6, §13).
- 경로 선택 계층(`PathSelector`)을 모듈 레이아웃에 명시. WireGuard 자체 로밍은 끔 (§3, §9).
- STUN 포트를 둘로 늘려 대칭 NAT 감지. persistent keepalive 분리 (§9).
- netstack 동시성 모델과 버퍼 예산 명시 (§10).
- auth-key를 독립 경로로 분리. 소유자/태그 모델 (§11).
- 위협 모델에 "hub 침해 = 피어 키 치환" 명시 (§12).
- hub 운영자 사전 준비 목록과 포트 수를 사실대로 수정 (§1, §2).
- WireGuard 상호운용 테스트, 경량 예산 CI 게이트를 마일스톤에 추가 (§14).
- 용어를 **jailnet**으로 통일.

---

## 1. 목표와 비목표

### 설계 원칙 (우선순위 순)

1. **경량화 (Lightweight)** — 상주 데몬이다. 아이들 RSS 30MB 이하, 콜드 스타트 50ms 이하,
   배포물은 런타임 의존성 없는 단일 실행 파일. 이 수치는 M0에서 실측하고 CI 게이트로 지킨다 (§4).
2. **사용성 (Usability)** — 가입하는 사람은 `jailscale up --invite <링크>` 한 줄로 끝. 초대하는
   사람은 `jailscale invite` 한 줄로 끝. 브라우저도 계정도 IdP도 없다. 키를 손으로 옮기는 절차가
   기본 경로에 있어선 안 된다. hub 운영자의 사전 준비는 DNS 이름과 방화벽 둘뿐이며(§7.1.2),
   그 목록을 늘리는 변경은 이 원칙에 대한 위반으로 취급한다.
3. **범용성 (Portability)** — root 권한 불필요, TUN 디바이스 불필요, 커널 모듈 불필요.
   native 바이너리를 못 쓰는 환경을 위해 순수 JVM fallback JAR도 항상 함께 배포한다.

### 비목표

- 공식 Tailscale 클라이언트/DERP와의 와이어 호환성 (독자 프로토콜로 간다)
- 커널 WireGuard 드라이버 연동 (v1 범위 밖. 데이터 평면은 표준 준수라 나중에 가능)
- Exit node, subnet router (v2 이후)
- Android / iOS 클라이언트. fallback JAR는 데스크톱/서버 JVM용이며 모바일 런타임은 대상이 아니다
- 피어 키 바인딩을 hub 없이 검증하는 기능 (Tailscale의 tailnet lock 상당. §12.5, §15)

---

## 2. 구성 요소 개요

```
        ┌──────────────────────────────────────────┐
        │                jailhub                   │   단일 프로세스
        │  ┌────────────────┐  ┌────────────────┐  │   TCP 80/443 + UDP 3478/3479
        │  │  Coordinator   │  │  DERP Relay    │  │
        │  │  등록·netmap    │  │  패킷 중계      │  │
        │  │  초대·승인·ACL  │  │  (내용 불가시)  │  │
        │  └────────────────┘  └────────────────┘  │
        │  ┌────────────────┐  ┌────────────────┐  │
        │  │  STUN Server   │  │  Admin (IPC +  │  │
        │  │  UDP 3478/3479 │  │  /admin 웹)    │  │
        │  └────────────────┘  └────────────────┘  │
        │  ┌──────────────────────────────────────┐│
        │  │  HTTP/1.1 + TLS 종단 + 내장 ACME      ││  TCP 80/443
        │  └──────────────────────────────────────┘│
        └───────▲──────────────────────▲───────────┘
                │ control (Noise)      │ control (Noise)
                │ + DERP relay         │ + DERP relay
        ┌───────┴────────┐     ┌───────┴────────┐
        │   jailscale    │     │   jailscale    │
        │   (node A)     │◄───►│   (node B)     │
        └────────────────┘ UDP └────────────────┘
                        직접 경로 (홀펀칭 성공 시)
```

**통합의 근거.** coordinator와 DERP를 한 프로세스에 두면 배포 단위가 하나, TLS 종단이 하나,
인증서가 하나가 된다. 게다가 DERP가 노드 명부를 이미 메모리에 들고 있으므로,
릴레이 접속 인증이 별도 토큰 교환 없이 공짜로 해결된다. Tailscale이 둘을 분리한 이유는
글로벌 릴레이 함대를 운영하기 위해서인데, 우리는 self-host 단일 노드가 주 사용처다.

**포트는 넷이다.** TCP 443(컨트롤 + DERP + `/join` + 관리 웹, hub가 TLS를 직접 종단),
TCP 80(ACME HTTP-01 검증과 HTTPS 리디렉트), UDP 3478과 3479(STUN). 전부 `jailhub` 프로세스
하나가 바인드한다. 앞에 프록시가 없는 것이 기본이다. STUN을 둘로 두는 이유는 §9.

---

## 3. 모듈 레이아웃

Maven 멀티모듈. 의존 방향은 위에서 아래로만 흐른다.

```
jailscale/
├── pom.xml                  parent (release=25, native 프로파일)
├── jailscale-crypto/        BLAKE2s · HKDF · X25519 · ChaCha20-Poly1305 · 키 타입/인코딩
├── jailscale-proto/         컨트롤 평면 메시지 + JSON 코덱 + DERP 프레이밍 + 최소 HTTP/1.1 파서 (crypto 의존)
├── jailscale-wire/          WireGuard 데이터 평면: Noise IK, transport, 피어 상태·타이머
│                            → 엔드포인트를 모른다. 패킷을 PeerTransport 인터페이스에 넘길 뿐
├── jailscale-netstack/      userspace TCP/IP: IP·ICMP·UDP·TCP, SOCKS5, 포트포워드
├── jailscale-node/          클라이언트 데몬 + CLI + 로컬 IPC      → 네이티브 바이너리 `jailscale`
│   └── path/                PathSelector: STUN·disco·홀펀칭·직접/DERP 경로 선택 (magicsock 상당)
└── jailscale-hub/           coordinator + DERP + STUN + 관리 IPC/웹  → 네이티브 바이너리 `jailhub`
```

바이너리를 둘로 나누는 이유는 클라이언트에 서버 코드가 섞이지 않게 해서 배포물을 작게
유지하기 위함이다. (native-image의 reachability 분석이 어차피 잘라내긴 하지만,
모듈 경계를 명시해두면 의존성 역류를 컴파일 타임에 막을 수 있다.)

**`jailscale-wire`는 UDP 주소를 모른다.** WireGuard 엔진은 "피어 X에게 이 바이트를 보내라"를
`PeerTransport`에 위임하고, 그 구현체인 `PathSelector`가 직접 경로와 DERP 중 무엇을 쓸지
정한다. 이 경계가 없으면 §9의 경로 승격/강등이 WireGuard 엔진 안으로 새어 들어간다.

---

## 4. GraalVM Native Image 규율

이 프로젝트의 모든 코드는 아래 규칙을 따른다. 나중에 고치는 게 아니라 처음부터 지킨다.

| 항목 | 규칙 | 이유 |
|---|---|---|
| 리플렉션 | 금지 | reachability metadata 관리 비용, 바이너리 비대화 |
| 동적 프록시 / 클래스로딩 | 금지 | native-image에서 사실상 불가 |
| DI 프레임워크 | 사용 안 함. 생성자 수동 배선 | Spring/Guice는 리플렉션 덩어리 |
| JSON | 자체 파서 + 수동 인코더 (`jailscale-proto`) | Jackson은 리플렉션 + 수 MB 증가. 메시지 스키마가 10여 개뿐이라 수동이 싸다 |
| HTTP 서버 | **자체 최소 HTTP/1.1 서버** (`jailscale-hub`) | JDK `com.sun.net.httpserver`는 Upgrade 후 소켓을 내주지 않아 §7.1의 채널을 못 만든다. 엔드포인트가 6개뿐이라 손수 쓰는 쪽이 싸다 (~300줄) |
| HTTP 클라이언트 | 노드: `SSLSocket` 위 자체 소형 HTTP/1.1 (~40줄). hub: JDK `java.net.http.HttpClient` (ACME) | 노드는 Upgrade가 필요해 JDK 클라이언트를 못 쓴다. 덕분에 노드 바이너리에서 `java.net.http`가 빠진다 |
| 로깅 | 자체 초경량 로거 (`System.Logger` 백엔드) | SLF4J+logback은 ServiceLoader + 리플렉션 |
| 암호 | JDK JCE (SunEC, SunJCE) + 자체 BLAKE2s | BouncyCastle은 native 설정이 번거롭고 크다 |
| TLS 서버 | JDK `SSLServerSocket` / `SSLContext` (`jailscale-hub`) | 이미 바이너리에 있다. 외부 TLS 종단 프록시 없음 |
| ACME 클라이언트 | 자체 구현 (`jailscale-hub`, ~600줄) | JWS ES256·JSON·HttpClient는 JDK와 우리 코드로 충분. CSR DER 인코딩만 손수 쓴다 (§7.1.2) |
| AWT / `java.awt.Desktop` | 금지 | 브라우저 열기에 AWT를 쓰면 native 바이너리에 GUI 툴킷이 딸려온다. `open` / `xdg-open` / `rundll32 url.dll,FileProtocolHandler`를 `ProcessBuilder`로 실행 |
| 프로세스 간 통신 | AF_UNIX 소켓 (`UnixDomainSocketChannel`, 모든 플랫폼) | Windows 10 1803+도 AF_UNIX를 지원한다. 명명된 파이프는 JDK 공개 API가 없어 FFM/JNI가 필요하다 |
| 스레딩 | Virtual threads 적극 사용. 단 핫패스는 예외 (§13) | GraalVM for JDK 21+ 에서 지원 |
| 빌드 시 초기화 | 화이트리스트 방식으로 신중히. JCE는 런타임 초기화 | 빌드 타임에 SecureRandom 시드가 고정되는 사고 방지 |

**알려진 성능 제약.** GraalVM native-image에는 HotSpot의 ChaCha20/Poly1305 intrinsic이 없다.
암복호 처리량의 상한은 순수 Java 구현이 정한다. M0에서 실측하고, 부족하면 `jailscale-crypto`에
자체 ChaCha20-Poly1305를 두는 옵션을 연다 (BLAKE2s와 같은 방식).

**빌드**

- 기본 프로파일: 일반 JVM 빌드 (`mvn test` 빠른 반복)
- `-Pnative`: `native-maven-plugin`으로 바이너리 생성
- CI 매트릭스: linux-amd64, linux-arm64, macos-arm64, macos-amd64, windows-amd64
- 매 릴리스마다 fallback으로 `jailscale-all.jar` (JVM 25 필요) 동봉 → **범용성 보증**

**경량 예산 CI 게이트 (M0부터)**

| 측정 | 기준 | 방법 |
|---|---|---|
| 노드 아이들 RSS | ≤ 30 MB | native `jailscale`이 hub에 붙어 netmap을 받은 뒤 60초 유휴 상태에서 측정 |
| 노드 바이너리 크기 | ≤ 40 MB (M0 실측 후 조정) | 릴리스 아티팩트 |
| 콜드 스타트 | ≤ 50 ms | `jailscale status` 실행 시간 (IPC 왕복 포함) |
| 암복호 처리량 | 기록만 (M0), 목표는 M1에서 설정 | 단일 스레드 ChaCha20-Poly1305 1280B 패킷 |
| hub 아이들 RSS | ≤ 50 MB (M2부터 게이트) | 노드 10대 접속, 인증서 발급 완료 후 유휴. hub는 경량 원칙의 주 대상이 아니지만 상한은 둔다 |

수치를 넘으면 빌드가 실패한다. 예산은 이유와 함께 PR로만 바꾼다.

**개발 환경 요구사항**

- `brew install graalvm` → GraalVM for JDK 25 계열. native-image 포함. (정확한 버전 표기는
  M0에서 고정한다.)
- Linux에서는 `gcc`, `zlib` 개발 헤더 필요

---

## 5. 키와 신원

노드마다 세 개의 X25519 키페어를 가진다. 용도를 분리하면 하나를 교체할 때 나머지가
영향받지 않고, 서로 다른 프로토콜에서 같은 정적 키를 재사용하는 암호학적 냄새를 피한다.

| 키 | 용도 | 수명 |
|---|---|---|
| **MachineKey** (`mkey:`) | 컨트롤 채널 Noise 핸드셰이크의 클라이언트 정적 키. 이 머신 자체를 식별 | 머신 수명 전체. 로그아웃해도 유지 |
| **NodeKey** (`nkey:`) | WireGuard 데이터 평면 정적 키. 피어 간 터널의 신원 | 가입 단위. 기본 만료 없음, 관리자 폐기 또는 `--node-key-ttl`로 종료 |
| **DiscoKey** (`dkey:`) | 경로 탐색(ping/pong) 메시지 봉인용 | 프로세스 재시작마다 갱신 가능 |

hub도 정적 키 하나를 가진다 (`hkey:`). 노드는 이 공개키를 미리 알고 접속한다.
hub 키의 회전 절차는 §7.1.1.

**노드 ID와 IP는 MachineKey에 묶인다.** NodeKey가 만료되어 재발급되어도 같은 머신은 같은
노드 ID와 같은 jailnet IP를 유지한다. 다른 사용자의 초대로 다시 가입하면 소유자만 바뀐다.

**인코딩.** WireGuard의 base64 관례 대신 `prefix:base64url-nopad` 형식을 쓴다.
프리픽스가 있으면 로그·설정 파일에서 키 종류를 눈으로 구분할 수 있고, 잘못된 자리에
붙여넣는 사고를 파싱 단계에서 잡는다. 예: `nkey:0J3B_2xQ...`

**저장 위치.** `$XDG_CONFIG_HOME/jailscale/node.json` (기본 `~/.config/jailscale/`),
파일 권한 0600. 윈도우는 `%LOCALAPPDATA%\jailscale\`이며 0600에 상당하는 ACL(현재 사용자만
읽기/쓰기)을 생성 시 설정한다.

---

## 6. 데이터 평면 — WireGuard (`jailscale-wire`)

프로토콜은 **WireGuard 표준을 그대로 준수**한다. 컨트롤 평면만 자체 설계하고 데이터
평면은 표준을 따르는 이유는, 검증된 설계에 공개 테스트 벡터가 있고, 나중에 커널
WireGuard와 붙일 여지를 남겨두기 위해서다. 표준 준수 주장은 M1에서 wireguard-go와의
상호운용 테스트로 검증한다 (§14).

`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`

**PSK는 v1에서 쓰지 않는다.** 표준대로 32바이트 0을 넣는다. hub가 피어 쌍마다 PSK를 배포하는
것은 나중에 추가할 수 있는 선택지로 남긴다.

### 메시지

| 타입 | 크기 | 역할 |
|---|---|---|
| 1 HandshakeInitiation | 148 B | 개시자 → 응답자 |
| 2 HandshakeResponse | 92 B | 응답자 → 개시자 |
| 3 CookieReply | 64 B | DoS 완화 (M4에서 구현) |
| 4 TransportData | 16 + N + 16 B | 암호화된 IP 패킷 (헤더 16 + 평문 N + 태그 16) |

TransportData 헤더: `[1B type][3B reserved][4B receiverIndex][8B counter LE]`,
그 뒤에 ChaCha20-Poly1305 암호문 (평문 IP 패킷 + 16B 태그).
논스는 `4B zero || 8B counter LE`. AAD는 비어 있다.

### 상태 머신과 표준 상수

각 피어는 최대 3개의 키페어를 동시에 들고 있다 (current / previous / next).

| 상수 | 값 | 의미 |
|---|---|---|
| REKEY_AFTER_TIME | 120 s | **개시자만** 이 시간이 지나면 다음 전송 전 재핸드셰이크 |
| REJECT_AFTER_TIME | 180 s | 이 시간이 지난 세션으로는 송수신 거부 |
| REKEY_AFTER_MESSAGES | 2^60 | 메시지 수 기준 재핸드셰이크 |
| REJECT_AFTER_MESSAGES | 2^64 − 2^13 − 1 | 메시지 수 기준 거부 |
| REKEY_TIMEOUT | 5 s | 핸드셰이크 재시도 간격 |
| REKEY_ATTEMPT_TIME | 90 s | 이 시간 동안 핸드셰이크 실패 시 포기 |
| KEEPALIVE_TIMEOUT | 10 s | 데이터 수신 후 보낼 게 없으면 빈 패킷 (passive keepalive) |

- **리플레이 방지**: 슬라이딩 윈도우 비트맵. 커널 구현과 같은 **8192** 비트. DERP 경유 시
  재정렬 폭이 커서 2048은 작다.
- **Passive keepalive**와 **persistent keepalive**는 다른 것이다. 전자는 위 표의 10초 규칙으로
  상대에게 "받았다"를 알린다. 후자는 NAT 매핑 유지가 목적이며 `PathSelector`가 결정한다 (§9).
- **엔드포인트 로밍은 끈다.** 표준 WireGuard는 인증된 패킷의 출발 주소로 피어 엔드포인트를
  갱신하지만, 우리는 경로 결정을 `PathSelector`에 일임한다. 두 주체가 엔드포인트를 두고
  경쟁하면 경로가 흔들린다. Tailscale도 같은 이유로 끈다.
- **타이머**: 단일 `ScheduledExecutorService`가 전 피어를 관리. 피어당 스레드 금지.
- **핸드셰이크 타임스탬프**(TAI64N)는 시계가 뒤로 가면 상대가 거부한다. RTC 없는 기기에서
  발생 가능. 오류 메시지에 이 원인을 명시한다.

### MTU

터널 MTU **1280** (IPv6 최소 MTU). 오버헤드 계산:
`1280 + 32(WG) + 8(UDP) + 20(IPv4) = 1340` — 어지간한 경로에서 프래그먼트 없이 통과.
IPv6 외부 경로는 1360. 터널 안 TCP MSS는 우리가 스택을 소유하므로 정확히 클램프한다:
IPv4 1240, IPv6 1220.

### 성능

- 패킷당 힙 할당 금지. **힙 배열 기반 `ByteBuffer` 풀**을 두고 재사용한다. direct 버퍼를 쓰지
  않는 이유: JCE `CipherSpi`의 `ByteBuffer` 경로는 배열 기반이 아니면 내부에서 임시 byte[]로
  복사한다. direct 풀은 할당 0 목표를 조용히 깨뜨린다. UDP I/O 쪽의 임시 direct 버퍼는 JDK가
  스레드별로 캐시하므로 GC 압력이 없다.
- `Cipher` 인스턴스는 스레드별로 재사용 (`Cipher.getInstance`는 비싸다).
- 암복호는 **UDP 수신 스레드에서 인라인**으로 수행한다 (§13과 동일). 별도 풀로 넘기면 컨텍스트
  스위치와 큐잉이 지연을 키운다. 수신 스레드는 기본 1개이며, 처리량이 필요하면 설정으로 늘린다.

---

## 7. 컨트롤 평면 — Coordinator (`jailscale-hub`)

### 7.1 전송 계층: TLS 위의 Noise (심층 방어)

노드 ↔ hub 통신은 **웹 PKI TLS 연결 안에서 Noise_IK 채널을 다시 여는** 이중 구조다.
운반체는 HTTP/1.1 Upgrade이며, 101 이후는 그냥 바이트 스트림이다.

```
TCP 443
 └─ TLS 1.3, ALPN http/1.1   (웹 PKI. 호스트명을 인증하고 최초 신뢰를 부트스트랩)
     └─ HTTP/1.1 Upgrade   POST /v1/noise, Upgrade: jailscale-control-v1
         └─ Noise_IK       (MachineKey ↔ hkey. CA를 신뢰하지 않아도 성립)
             └─ [2B len BE][Noise transport 메시지]   프레임 1개 (§8)
```

**JDK의 HTTP 스택은 여기에 쓸 수 없다.** `com.sun.net.httpserver`는 Upgrade 후 소켓을
핸들러에 내주지 않고, `java.net.http.HttpClient`도 101 응답 이후의 연결을 넘겨주지 않는다.
따라서 양쪽 모두 손수 쓴다.

- **hub**: `SSLServerSocket`(443) 및 `ServerSocket`(80, 그리고 `--behind-proxy`의 루프백) 위의
  최소 HTTP/1.1 서버. 요청 줄과 헤더를 파싱해 다섯 개 엔드포인트(`/v1/key`, `/v1/noise`,
  `/join/*`, `/admin/*`, `/.well-known/acme-challenge/*`)로 분기하고, `/v1/noise`는 101을 쓴 뒤 소켓을 Noise 핸들러에 넘긴다. 300줄 안팎.
- **노드**: `SSLSocket` 위의 소형 HTTP/1.1 클라이언트. 요청 한 줄과 헤더 몇 개를 쓰고 응답
  줄을 파싱한다. 40줄 안팎. `/v1/key` GET도 이 클라이언트로 처리하므로 **노드 바이너리에는
  `java.net.http` 모듈이 들어가지 않는다.** M0 예산 측정에서 이 차이를 기록한다.

**WebSocket을 쓰지 않는 이유.** v2 초안에서 검토했다. JDK 클라이언트가 내장이라는 장점은
40줄짜리 클라이언트 앞에서 의미가 없고, 대신 클라이언트→서버 프레임의 4바이트 XOR 마스킹이
DERP 데이터 경로에서 매 바이트를 한 번 더 만지게 하며, 프레임 헤더·조각화·close 의미론이
따라온다. WS가 이기는 경우는 우리가 통제하지 않는 프록시(Cloudflare, ALB, 일부 WAF)가
`Upgrade: websocket`만 통과시킬 때뿐인데, 기본 배포에는 프록시가 없다. `--behind-proxy`로
nginx를 앞에 두는 경우에도 nginx는 Upgrade 값을 검사하지 않고 넘긴다. Tailscale의 ts2021이
같은 방식으로 headscale 앞의 nginx를 통과한다. Cloudflare 프록시 뒤는 지원하지 않으며,
그런 운영자는 DNS-only 모드로 프록시를 끄면 된다. WS 폴백은 두지 않는다.

ALPN을 `http/1.1`로 고정하는 이유: HTTP/2에는 Upgrade가 없다. `SSLParameters`로 직접
지정한다.

**Noise 메시지 크기.** Noise 스펙상 transport 메시지는 최대 65535B다. 길이 프리픽스가 2바이트인
이유다. WireGuard 패킷은 1400B 미만이라 문제없고, CTRL 페이로드(netmap)가 그보다 크면
`CTRL_MORE` 프레임으로 분할한다 (§8).

**왜 TLS를 벗기지 않는가.** IdP가 없으니 브라우저가 hub에 갈 일이 줄었고, Noise만으로도
컨트롤 채널은 인증된다. 그럼에도 기본값이 TLS인 이유는 셋이다.

1. **hkey 부트스트랩.** 노드가 호스트명만 알고 접속하려면 첫 접촉에서 hub 키를 믿을 근거가
   필요하고, 그것이 웹 PKI다 (§7.1.1). TLS를 빼면 초대 링크에 키 지문을 실어야 하며, 초대 없이
   두드리는 경로(§11.4)는 TOFU가 된다.
2. **브라우저 경로가 남는다.** `/join/<token>` 안내 페이지와 `/admin`이다. 평문이면 브라우저가
   경고를 띄우고 관리 세션 쿠키를 지킬 수 없다.
3. **망 통과.** 기업 방화벽과 중간 박스는 443의 TLS는 통과시키지만 평문 포트의 업그레이드나
   정체불명의 바이너리 스트림은 변형하거나 차단한다. 443에서 TLS가 아닌 트래픽을 막는 DPI도 있다.

인증서는 hub가 스스로 받으므로(§7.1.2) 운영자에게 비용이 없다. 따라서 TLS를 벗겨 얻는 것은
80 포트 하나이고, 잃는 것은 위 셋이다. 다만 OAuth가 사라진 지금 `--no-tls` 모드는 설계상
성립한다. §15에 후보로 둔다.

**왜 그런데도 Noise를 안에 넣는가.** TLS를 대체하려는 것이 아니라 겹치는 것이다.
웹 PKI의 위협 모델에는 CA 침해와, 사내 루트 CA를 설치한 기업 MITM 프록시가 남는다.
그 둘은 TLS를 뚫지만 고정된 hkey로 수행하는 Noise 핸드셰이크는 뚫지 못한다.
Tailscale이 정확히 이 구조를 쓴다(ts2021: TLS 바깥, Noise IK 안쪽).
그리고 우리에게는 Noise IK 엔진이 데이터 평면용으로 이미 있으므로 한계 비용이 낮다.

**Noise 파라미터.** `Noise_IK_25519_ChaChaPoly_BLAKE2s`, 프롤로그 `jailscale-control-v1`.
WireGuard의 mac1/mac2/타임스탬프 확장은 쓰지 않는다. TLS+TCP 아래에 있으므로 그 DoS 방어가
불필요하고, 순수 Noise IK가 재사용에 더 깔끔하다. 프롤로그의 버전 문자열은 핸드셰이크 해시에
섞이므로 호환되지 않는 버전끼리는 핸드셰이크 자체가 실패한다.

### 7.1.1 hub 키 부트스트랩과 회전

노드가 알아야 하는 것은 **호스트명 하나뿐**이다.

```
1. jailscale up --hub hub.example.com
2. GET https://hub.example.com/v1/key         ← 평범한 TLS, 웹 PKI로 검증
     → { "hubKey": "hkey:...", "nextHubKey": null, "notAfter": 1789000000 }
3. 노드가 그 키를 node.json에 고정(pin)
4. POST https://hub.example.com/v1/noise      ← TLS 안에서 HTTP/1.1 Upgrade
     → 고정된 hkey로 Noise_IK 개시
5. 이후 모든 접속은 고정된 키를 사용. 불일치는 경고와 함께 하드 실패
```

최초 접촉의 신뢰는 웹 PKI가 담당하고, 그 이후로는 CA와 무관해진다. 공격 창이 최초
한 번으로 축소되며, 이는 Tailscale과 동일한 트러스트 모델이다.

**회전.** `notAfter`는 hub 키의 만료 예정 시각이다. 만료를 하드 실패로 만들지 않기 위한 절차:

1. 운영자가 `jailhub key rotate --grace 30d`를 실행하면 hub가 `next` 키를 생성한다.
2. 이후 붙는 모든 노드에게 컨트롤 채널로 `HubKeyRotation{ nextHubKey, activatesAt }`를 보낸다.
   이 메시지는 옛 키로 인증된 Noise 채널 안에서 오므로 별도 서명이 필요 없다.
   노드는 `next`를 node.json에 함께 저장한다.
3. 유예 기간 동안 hub는 두 키 모두로 핸드셰이크를 받는다. 노드는 `current`로 시도하고
   실패하면 `next`로 재시도한다.
4. `activatesAt` 이후 hub는 옛 키를 버린다. `/v1/key`는 새 키만 돌려준다.
5. 유예 기간 동안 한 번도 접속하지 않은 노드는 두 키 모두 실패한다. 이 경우에만 노드는
   "hub 키가 바뀌었습니다. 다시 신뢰하시겠습니까 (y/N)"를 물은 뒤 `/v1/key`로 재부트스트랩한다.
   무인 노드는 실패 상태로 남고 로그에 이유를 남긴다.

**강화 옵션 `--hub-key hkey:...`** — 기본값이 아니다. 웹 PKI를 신뢰하지 않는 배포,
에어갭 환경, 그리고 개발용이다. 명시적 `--hub-key`가 주어지면 `/v1/key` 조회를 건너뛰고
Noise가 서버 인증을 완결하므로, **컨트롤 채널에 한해** TLS 인증서 검증을 완화해도 보안 손실이
없다.

단 이것으로 자체 서명 인증서 개발이 끝나지는 않는다. `/join/` 안내 페이지와 `/admin`은
브라우저가 가는 경로이고, 브라우저는 `--hub-key`를 모른다. 개발 경로는 `mkcert` 등으로 만든
로컬 CA를 브라우저와 노드 양쪽에 신뢰시키는 것이며, 참조 스크립트를 레포에 둔다.

공개키 자체는 비밀이 아니므로 노출은 위험이 아니다(개인키 없이는 사칭 불가, Noise의
임시 키가 전방향 비밀성 제공). 위험은 오직 **치환**이며, 위 부트스트랩은 그 창을
최초 1회로 좁힌다. 클릭 가능한 `https://...?key=` 형태로 키를 전달하는 것은
금지한다 — 링크처럼 생긴 것은 사람이 검증하지 않는다.

선택적 배포 경로로 `_jailscale.<hub-host>` TXT 레코드를 지원할 수 있다(호스트명과 동일
수준의 신뢰를 재사용).

### 7.1.2 hub의 TLS 조달과 운영자 사전 준비

hub는 TLS를 **직접 종단**한다. 앞에 Caddy나 nginx를 두지 않는다. 프로세스가 둘이 되면 설치·설정·
장애 원인 추적이 둘이 되어 사용성에 손해이고, 프록시 배포 경로가 하나 더 생겨 범용성에도
손해다. JDK의 TLS 서버는 이미 바이너리에 있으므로 경량화에는 비용이 없다.

hub 운영자가 `jailhub serve` 전에 해야 하는 일은 아래가 전부이며, 이 목록이 사용성 원칙의
경계다.

| # | 준비 | 비고 |
|---|---|---|
| 1 | 공인 DNS 이름 → hub의 공인 IP | A 또는 AAAA. `hub.example.com`. **프록시 없이 직접** (Cloudflare는 "DNS only" 회색 구름) |
| 2 | 방화벽: TCP 80, TCP 443, UDP 3478, UDP 3479 | 80은 ACME 검증용. 인증서를 직접 주면 80은 불필요 |

둘뿐이다. 인증서는 hub가 스스로 받고, 계정·IdP·앱 등록은 없다. 첫 실행은
`jailhub serve --base-url https://hub.example.com` 한 줄이며, 콘솔에 첫 초대 링크가 찍힌다 (§11.5).

| TLS 방식 | 용도 | 비고 |
|---|---|---|
| 내장 ACME HTTP-01 | **기본값.** `--base-url`의 호스트명으로 자동 발급·갱신 | Let's Encrypt 기본. `--acme-directory`로 교체 가능 |
| `--tls-cert` / `--tls-key` | 인증서를 이미 보유한 경우, 사내 CA, 80 포트를 열 수 없는 경우 | 파일 변경 감지 시 리로드 |
| `--behind-proxy` | 이미 nginx 등이 있는 운영자 | hub는 루프백 평문 HTTP. `X-Forwarded-For` 신뢰. Upgrade 헤더 전달과 유휴 타임아웃 300초를 문서화 |
| `--hub-key` 고정 | 개발 / 에어갭 | 컨트롤 채널만 TLS 검증 완화 가능 (§7.1.1) |

#### 내장 ACME의 동작

```
jailhub serve --base-url https://hub.example.com ...
 │
 ├─0. $JAILHUB_STATE/tls/ 에 유효한 인증서가 있으면 → 즉시 443 개방, 11번으로
 ├─1. 80 포트 리스너 기동. /.well-known/acme-challenge/* 만 응답, 나머지는 https로 301
 ├─2. 자가 진단 (둘 다 통과해야 발급 시작. 실패하면 원인을 콘솔에 출력하고 대기)
 │     a. TCP: 공인 DNS로 자기 호스트명을 풀고, 그 IP의 80 포트로 임시 토큰을 요청해 자기
 │        자신이 응답하는지 확인 → DNS 불일치 / 80 차단 / 다른 서버가 응답 을 구분
 │     b. UDP: 같은 IP의 3478 포트로 무작위 txid의 STUN 요청을 보내고 자기 STUN 서버가 그
 │        txid를 받았는지 확인 → "UDP가 hub에 닿지 않음: DNS가 프록시(Cloudflare 주황 구름)를
 │        거치거나 방화벽이 막고 있음". a만으로는 프록시 뒤를 못 잡는다. Cloudflare 엣지가
 │        80을 hub로 전달해 주기 때문이다. UDP는 어떤 HTTP 프록시도 전달하지 않는다
 │     이 검사는 Let's Encrypt의 실패 레이트리밋을 아끼고, "인증서는 받았는데 노드가 안 붙는"
 │     상태를 사전에 막는다. 1:1 NAT 뒤의 클라우드 VM처럼 공인 IP가 인터페이스에 없어도 동작한다.
 │     실패하면 60초마다 재시도하므로 DNS를 고친 뒤 재시작이 필요 없다.
 │     한계: 자기 공인 IP로 보낸 패킷이 되돌아오려면 NAT 헤어핀이 필요한데, 가정용 공유기
 │     뒤에서 포트포워딩으로 hub를 돌리면 헤어핀이 안 되는 기종이 많다. 그 경우 `--no-selfcheck`로
 │     건너뛴다. 이때는 노드 쪽 `jailscale netcheck`가 "TLS는 되는데 STUN이 안 됨"을 보고해
 │     프록시/방화벽 문제를 대신 잡는다
 ├─3. 계정 키(EC P-256) 없으면 생성 → tls/account.key (0600). newAccount, 약관 동의
 │     (--acme-email 은 선택, 만료 알림용)
 ├─4. newOrder { identifiers: [dns: hub.example.com] }
 ├─5. authorization 조회 → http-01 챌린지의 token 획득
 │     keyAuthorization = token + "." + base64url(SHA-256(계정 JWK thumbprint))
 ├─6. 80 리스너에 GET /.well-known/acme-challenge/<token> → keyAuthorization 등록
 ├─7. 챌린지 "준비됨" POST. CA가 여러 지점에서 80 포트로 확인
 ├─8. authorization 상태를 폴링 (valid 까지, 최대 60초)
 ├─9. 인증서 키(EC P-256) 생성 → PKCS#10 CSR을 DER로 직접 인코딩 → finalize
 ├─10. order 상태 폴링 → 인증서 체인 다운로드 → tls/cert.pem, tls/key.pem (0600)
 ├─11. SSLContext 구성, 443 개방. 발급까지 보통 수 초
 └─12. 갱신: 하루 한 번 검사, **잔여 수명이 전체의 1/3 이하**이면 4~10 반복 (90일 인증서면
        30일 전. CA/B Forum 일정에 따라 수명이 47일까지 줄어도 규칙이 유지된다). 성공 시 SSLContext 교체
        (새 연결부터 적용, 기존 연결 유지). 실패 시 지수 백오프로 재시도하며 옛 인증서로 계속
        서빙. 만료 7일 전부터는 콘솔과 /admin 에 경고
```

- **JWS.** 보호 헤더 `{alg: ES256, nonce, url, jwk|kid}`. nonce는 `newNonce` 또는 직전 응답의
  `Replay-Nonce`. 서명은 JDK `SHA256withECDSA`가 DER로 내주므로 JWS의 raw `R||S` 64바이트로
  변환한다. 이 변환을 빠뜨리면 CA가 모든 요청을 거부한다.
- **CSR.** JDK에는 PKCS#10 공개 API가 없다. 최소 DER 작성기(SEQUENCE·INTEGER·OID·BIT STRING·
  UTF8String·SET, ~80줄) 위에 `CertificationRequestInfo{version 0, subject CN, SubjectPublicKeyInfo,
  extensionRequest[subjectAltName dns]}`를 만들고 ECDSA로 서명한다 (~120줄).
- **저장.** `tls/account.key`, `tls/key.pem`, `tls/cert.pem`. 백업 대상은 `$JAILHUB_STATE` 전체다.
- **지원 범위.** ACME v2, http-01만. External Account Binding(ZeroSSL 등)은 v1 밖.
  tls-alpn-01은 X.509 자체 서명 인증서 생성까지 손수 써야 해서 §15로 보낸다.
- **80 포트를 못 여는 환경**은 `--tls-cert/--tls-key`로 간다. certbot의 DNS-01 등 외부 도구로
  받은 인증서를 파일로 주면 hub가 변경을 감지해 리로드한다.
- **포트 바인딩 권한.** Linux에서 80/443은 root 또는 `CAP_NET_BIND_SERVICE`가 필요하다. 참조
  systemd 유닛은 전용 사용자 `jailhub` + `AmbientCapabilities=CAP_NET_BIND_SERVICE`로 root 없이
  띄운다. macOS는 비특권 바인딩이 허용된다. `--listen`으로 포트를 바꿀 수 있지만 ACME http-01은
  80을 요구하므로 그때는 `--tls-cert`로 간다.
- **Cloudflare 등 프록시형 DNS.** 레코드를 "DNS only"로 두면 설계대로 동작하고 Cloudflare는
  이름 해석만 담당한다. "Proxied"는 지원하지 않는다. 엣지가 `Upgrade: websocket` 외의 업그레이드를
  자르고 UDP를 전달하지 않아 컨트롤 채널과 STUN이 모두 죽는다. Cloudflare Tunnel도 같은 이유로
  불가. 자가 진단 2-b가 이 상태를 잡는다.

**v1 결정을 뒤집는 이유.** v1은 "600줄 보안 민감 코드로 얻는 것이 Caddy 설치 생략뿐"이라
내장 ACME를 거부했다. 그 계산은 Caddy를 기본 배포에 넣는다는 전제 위에 있었고, 그 전제가
사용성과 범용성을 깎는다. Caddy를 빼면 600줄이 사는 것은 "외부 도구 0, 프로세스 1, 설정 파일 1"
이며, 그것이 원칙 2가 요구하는 것이다. headscale이 Go의 autocert로 같은 것을 내장한 선례가 있다.
실패 모드는 "인증서를 못 받음"이고 `--tls-cert`로 우회 가능하므로 잠금 위험은 없다.

### 7.1.3 WireGuard와의 관계

컨트롤 평면이 WireGuard와 닮아 보이는 것은 의도된 것이며, 무엇이 같고 다른지는 명확하다.

**같은 것 — 암호 코어.** 컨트롤 채널도 (TLS 안쪽에서) Noise_IK를 쓰므로 DH·KDF·AEAD·해시가
동일하고 `jailscale-crypto`를 그대로 쓴다. 핸드셰이크 상태 머신은 Noise 프레임워크 부분만
공유하고, WireGuard 고유 확장(mac1/mac2, 타임스탬프, 쿠키)은 컨트롤에서 쓰지 않는다.
세션 관리도 갈린다 — WireGuard는 데이터그램 지향(카운터, 리플레이 윈도우, 120초 리키),
컨트롤은 스트림 지향(순서 보장, 리키 없음)이다.

**다른 것 — 내용물.** WireGuard에는 컨트롤 평면이 *존재하지 않는다*. 그것이 설계 철학이다.
피어·엔드포인트·AllowedIP를 사람이 손으로 설정하며, 노드 등록·신원 인증·IP 할당·피어
발견·NAT 조율·키 만료·ACL 배포·DNS가 전부 없다. 그 빈칸이 이 프로젝트가 설계하는 대상이다.

**왜 컨트롤 트래픽을 WireGuard 터널 안에 넣지 않는가.** 검토했으나 부트스트랩이 순환한다.
hub와 터널을 맺으려면 hub의 키와 엔드포인트가 필요한데 그것이 부트스트랩하려는 대상이고,
등록 전 노드에는 IP가 없으며, DERP는 자신이 실어 나를 터널 안에서 돌 수 없다. 또한 등록에
userspace TCP 스택이 선행되어야 해서 M5가 M2보다 앞서는 의존성 역전이 생긴다.

### 7.2 API

Noise 채널 위의 `CTRL` 프레임에 실리는 JSON 메시지. 모든 메시지는 `{"t": "<타입>", ...}`.

| 메시지 | 방향 | 역할 |
|---|---|---|
| `Hello` | N→H | **핸드셰이크 직후 첫 메시지.** `proto`(정수), `version`(문자열), `os` |
| `HelloResponse` | H→N | `proto`, `minProto`, `version`. 노드의 `proto < minProto`면 `Goodbye` |
| `Goodbye` | 양방향 | `reason`: `upgrade-required`, `key-expired`, `revoked`, `shutdown` |
| `RegisterRequest` | N→H | NodeKey·hostname·os 제출. `invite`, `code`, `authKey` 중 하나를 동봉하거나 없음(두드리기) |
| `RegisterResponse` | H→N | `approved{nodeId, addrs, user}` 또는 `pending` 또는 `rejected{reason}` |
| `InviteCreate` | N→H | 멤버 노드의 초대 발급 요청. `user?`, `uses`, `ttl` (§11.2) |
| `InviteCreated` | H→N | `url`, `code`, `expiresAt` |
| `AdminLink` | N→H / H→N | 관리자 노드가 `/admin` 일회용 로그인 URL을 요청 (§7.6) |
| `MapRequest` | N→H | netmap 구독 시작 (스트림 유지) |
| `MapResponse` | H→N | netmap **전문**. `seq` 단조 증가. 변경 시마다 push |
| `EndpointUpdate` | N→H | STUN 결과·로컬 후보 엔드포인트·NAT 유형 보고 |
| `HubKeyRotation` | H→N | §7.1.1 |
| `Ping` / `Pong` | 양방향 | **요청 시** 왕복 시간 측정 (`jailscale netcheck`). 생존 확인은 §8의 `KEEPALIVE`가 담당하며 둘을 겹치지 않는다 |

**버전 정책.** `proto`는 메시지 스키마와 DERP 프레임 집합의 버전이다. hub는 `minProto` 이상을
받는다. 노드가 hub보다 새 `proto`를 말하면 hub의 `proto`로 낮춰 동작한다. 프롤로그 문자열
`jailscale-control-v1`의 숫자는 Noise 파라미터가 바뀔 때만 올린다.

**MapResponse는 v1에서 전문만 보낸다.** 델타는 시퀀스 추적과 재동기화 규칙이 따라와야 하고,
수백 노드까지는 전문 JSON이 수십 KB라 문제가 안 된다. 델타는 §15. `seq`는 지금부터 붙여서
나중에 델타를 추가할 때 와이어 변경이 없게 한다.

`MapResponse`는 long-poll이 아니라 **열린 스트림 위의 서버 푸시**다. Noise 채널이
이미 장수명 연결이므로 DERP와 같은 연결을 공유할 수 있다 (§8).

### 7.3 netmap

netmap은 **ACL로 필터링해서** 배포한다. 노드에게는 그 노드가 도달할 수 있는 피어만 보낸다.
netmap이 담는 정보(호스트명·사용자·공인 엔드포인트·온라인 여부)는 그 자체로 민감하므로,
배포 범위가 도달 가능 범위를 넘어서는 안 된다. 자세한 근거는 §12.3.

```json
{
  "t": "MapResponse",
  "seq": 42,
  "selfNodeId": 7,
  "dnsSuffix": "example.jail.net",
  "nodes": [
    { "id": 3, "nodeKey": "nkey:...", "discoKey": "dkey:...",
      "name": "laptop", "user": "alice", "tags": [],
      "addrs": ["100.64.0.3/32", "fd7a:5ca1:e000::3/128"],
      "endpoints": ["203.0.113.9:41641", "192.168.1.5:41641"],
      "online": true, "lastSeen": 1757500000 }
  ],
  "dns": { "nameserver": "100.100.100.100" },
  "packetFilter": [ { "srcIps": ["100.64.0.0/10"], "dstPorts": [{"ip":"100.64.0.7","ports":"0-65535"}] } ]
}
```

- `dnsSuffix`가 MagicDNS 이름의 접미사다. `laptop.example.jail.net`. hub 설정 `--dns-suffix`,
  기본값은 hub 호스트명.
- `packetFilter`는 **수신 노드의 netstack이 인바운드에 적용**한다. 송신 측 필터는 두지 않는다.
  netmap 필터링이 이미 도달 불가 피어를 숨기고, 수신 측 검사만이 상대를 신뢰하지 않는
  유일한 지점이기 때문이다.
- `tags`는 auth-key로 등록된 무인 노드의 소유 표시 (§11.5). ACL 정책에서 주어로 쓴다.
- `derpHome`은 두지 않는다. DERP가 hub 하나뿐이다. 다중 릴레이는 §15.

### 7.4 주소 할당

- IPv4: `100.64.0.0/10` (RFC 6598 CGNAT)에서 노드당 `/32`
- IPv6: `fd7a:5ca1:e000::/48` (ULA, 설정 가능)에서 노드당 `/128`. 하위 비트 = 노드 ID
- 할당은 hub가 단조 증가 노드 ID로 결정론적으로 계산 → 별도 IPAM 상태 불필요
- **예약**: ID 0은 쓰지 않는다. `100.100.100.100`(MagicDNS 네임서버)에 해당하는 ID는 건너뛴다.
- 노드 ID는 MachineKey에 묶여 재등록해도 유지된다 (§5). 삭제된 노드의 ID는 재사용하지 않는다.
  22비트 공간이라 고갈은 현실적 문제가 아니다.

### 7.5 저장소

**파일 기반.** append-only JSON Lines 이벤트 로그 + 인메모리 상태. 재시작 시 리플레이.

```
$JAILHUB_STATE/          (기본 /var/lib/jailhub 또는 ~/.local/share/jailhub)
├── hub.key              hub 정적 개인키 (0600). 회전 중이면 hub.key.next도 존재
├── state.jsonl          이벤트 로그 (node-registered, node-expired, user-added, ...)
├── state.snapshot       주기적 스냅샷 (로그 압축)
├── jailhub.lock         프로세스 락. 두 번째 jailhub serve는 즉시 실패
├── jailhub.sock         관리 IPC 소켓 (§7.6)
└── tls/                 account.key · key.pem · cert.pem (0600). 내장 ACME 산출물 (§7.1.2)
```

- 이벤트는 쓰기 후 `fsync`. 스냅샷은 임시 파일에 쓰고 `rename`으로 원자 교체. 교체 후 그
  시점까지의 로그를 잘라낸다.
- 상태 디렉터리에 쓰는 프로세스는 `jailhub serve` 하나뿐이다. 관리 명령은 IPC로 서버에
  요청한다. 로그에 직접 쓰는 관리 명령은 없다.

**근거.** SQLite(JNI)나 임베디드 DB는 native-image에서 골칫거리고 바이너리를 키운다.
노드 수천 대까지는 인메모리 맵이 압도적으로 빠르고 단순하다. 규모가 필요해지면
`NodeStore` 인터페이스 뒤에 Postgres 어댑터를 붙인다 (pgjdbc는 native 지원이 양호).

### 7.6 관리 IPC와 관리 웹

`jailhub user approve`, `jailhub invite create`, `jailhub key rotate` 같은 관리 명령은 별도
프로세스다. 상태가 인메모리이므로 **실행 중인 서버에 요청**해야 한다.

- 전송: AF_UNIX 소켓 `$JAILHUB_STATE/jailhub.sock` (0600). Windows도 AF_UNIX (§4).
  소켓 파일 권한이 곧 인가다. 네트워크 포트는 열지 않는다.
- 프로토콜: 줄 단위 JSON 요청/응답. `jailscale-proto`의 코덱을 재사용.
- 명령: `node list|approve|deny|remove|rename`, `user list|remove`, `invite create|list|revoke`,
  `authkey create|list|revoke`, `admin add|remove|login-link`, `key rotate`, `status`.

**관리 웹 `/admin`.** 승인 큐가 있는 이상 관리자가 hub 셸에 들어가야만 승인할 수 있다면
사용성 원칙 위반이다. 최소 페이지를 v1에 둔다.

- 인증: 비밀번호도 IdP도 없다. **관리자 노드의 MachineKey가 신원이다.** 관리자가 자기 노드에서
  `jailscale admin`을 치면 노드가 Noise 채널로 `AdminLink`를 요청하고, hub가 60초짜리 일회용
  URL을 돌려주면 CLI가 브라우저를 연다. URL 방문 시 세션 쿠키 `HttpOnly; Secure; SameSite=Lax`
  발급. 노드가 없는 상황(첫 설치, 복구)은 hub 셸에서 `jailhub admin login-link`.
- 기능: 대기 큐 승인/거부, 노드 목록·이름 변경·삭제, 초대 발급, auth-key 발급, 초대 정책 토글.
  이것뿐이다.
- 구현: 서버 렌더링 HTML, JS 없음, CSS 인라인. 템플릿 엔진 없이 문자열 조립.

---

## 8. DERP 릴레이 (`jailscale-hub`)

컨트롤 채널과 **같은 Noise 연결을 공유**한다. 별도 접속·별도 인증이 없다.

프레임 포맷: `[2B len BE][Noise transport 메시지]`, 복호한 평문은 `[1B type][payload]`.
len은 Noise 암호문 길이(최대 65535)다.

| 타입 | 페이로드 | 방향 |
|---|---|---|
| `SEND_PACKET` | `[32B dstNodeKey][WG 패킷]` | N→H |
| `RECV_PACKET` | `[32B srcNodeKey][WG 패킷]` | H→N |
| `PEER_PRESENT` | `[32B nodeKey]` | H→N |
| `PEER_GONE` | `[32B nodeKey]` | H→N |
| `CTRL` | `[JSON]` | 양방향 (§7.2 메시지) |
| `CTRL_MORE` | `[JSON 조각]` | 양방향. 마지막 조각은 `CTRL`로 보낸다 (65535B 초과 시) |
| `KEEPALIVE` | 없음 | 양방향. **25초 주기**, 60초 무응답 시 연결 종료 |

릴레이는 페이로드를 **읽지 못한다** — WireGuard로 종단간 암호화되어 있고, hub는
피어의 NodeKey 개인키를 갖고 있지 않다. hub는 목적지 키를 보고 해당 노드의 연결로
바이트를 옮길 뿐이다. `srcNodeKey`는 hub가 연결의 신원으로 채운다. 노드가 보낸 값은 없다.

**릴레이 조건.** 등록이 완료되어 NodeKey가 MachineKey에 바인딩된 연결만 `SEND_PACKET`을 보낼
수 있다. 대기(pending) 상태의 연결이 보낸 릴레이 프레임은 버린다. 목적지가 송신자의 netmap에
없는 노드(ACL로 가려진 노드)면 버린다. 이것은 보안 경계가 아니라 증폭 방지다.
보안 경계는 수신 측 WireGuard가 모르는 키를 거부하는 것이다.

**동시성.** 노드당 연결 1개, virtual thread 2개(read/write) + **두 개의 바운드된 아웃바운드 큐**.

| 큐 | 내용 | 포화 시 |
|---|---|---|
| control (우선) | `CTRL`, `CTRL_MORE`, `KEEPALIVE`, `PEER_*`, `HubKeyRotation` | 버리지 않는다. 큐가 차면 그 연결을 끊는다. 노드는 재접속해 netmap 전문을 다시 받는다 |
| data | `RECV_PACKET` | **버린다** (UDP 의미론 유지, 백프레셔로 hub가 멈추지 않게). WireGuard 핸드셰이크 패킷(타입 1·2)은 큐 앞쪽에 넣는다 |

writer는 control 큐를 먼저 비운다. v1에서 큐 하나로 뒀던 설계는 netmap 푸시나 keepalive가
데이터 폭주에 밀려 드롭될 수 있었다.

- 같은 MachineKey로 두 번째 연결이 오면 옛 연결을 `Goodbye{shutdown}`으로 닫고 새 연결이 이긴다.
  재접속이 옛 연결의 타임아웃보다 빠른 경우가 흔하다.
- 연결 소켓에 `TCP_NODELAY`. 프레임이 작고 지연이 처리량보다 중요하다.
- hub는 누가 누구에게 얼마나 보내는지를 본다. 내용은 못 보지만 메타데이터는 본다 (§12).

---

## 9. NAT 트래버설 (`jailscale-node/path`)

Tailscale과 같은 철학: **일단 붙이고, 그 다음에 빠르게 만든다.** 이 절의 주체는
`PathSelector`이며, `jailscale-wire`의 `PeerTransport` 구현체다 (§3).

1. 노드가 뜨면 즉시 DERP 경로로 모든 피어와 통신 가능 (지연 있지만 100% 동작)
2. 백그라운드에서 STUN(hub의 UDP 3478과 3479)으로 자기 공인 엔드포인트와 NAT 유형 발견
3. `EndpointUpdate`로 hub에 보고 → netmap을 통해 피어들에게 전파
4. 피어의 후보 엔드포인트 각각에 **disco ping**을 직접 UDP로 발사 (동시 홀펀칭).
   동시에 DERP로 `CallMeMaybe{myEndpoints}`를 보내 상대도 같은 순간에 쏘게 한다
5. disco pong이 돌아온 경로가 있으면 → 그 경로로 **승격**. DERP는 폴백으로 유지
6. 직접 경로가 5초간 무응답이면 → DERP로 **강등**

**STUN 포트가 둘인 이유.** 서버가 하나뿐이면 매핑된 주소는 알 수 있어도 그 매핑이
목적지에 따라 달라지는지(대칭 NAT)는 알 수 없다. 같은 IP의 두 포트에 물어 매핑 포트가
다르면 endpoint-dependent 매핑이다. 그 경우 상대가 쏘는 홀펀칭은 실패하므로, 시도는 하되
승격 기대를 접고 DERP를 유지한다. 양쪽 다 대칭이면 시도조차 하지 않는다.

**heartbeat와 persistent keepalive는 다른 것이다.**

| 메커니즘 | 주기 | 목적 | 조건 |
|---|---|---|---|
| disco heartbeat | 2초 | 직접 경로 생존 확인. 5초(pong 2회 이상 유실) 무응답 시 강등 | 최근 5분 내 트래픽이 있는 활성 직접 경로 |
| persistent keepalive | 25초 | NAT 매핑 유지. 빈 WG 패킷 | 유휴 직접 경로가 NAT 뒤에 있을 때. `--keepalive=0`으로 끔 (배터리 기기) |
| WG passive keepalive | 10초 규칙 | §6 | 항상 |

유휴 경로가 keepalive를 끈 채로 만료되면 다음 트래픽에서 DERP로 시작해 다시 홀펀칭한다.
Tailscale도 이렇게 동작한다.

**disco 프로토콜**: `[6B magic "JSdisc"][32B senderDiscoPub][12B nonce][sealed]`.
봉인은 X25519(sender disco, receiver disco) → HKDF → ChaCha20-Poly1305(IETF, 96비트 논스).
JDK에는 XChaCha20이 없어 24B 논스는 쓸 수 없다. 논스는 무작위이며, 같은 키 쌍에서 2^32개를
넘기 전에 충돌 위험이 생기는데 heartbeat 2초 주기로는 수십 년 분량이고 DiscoKey는 프로세스
재시작마다 바뀐다. 메시지는
`ping{txid, srcEndpoint}`, `pong{txid, srcEndpoint, observedEndpoint}`, `callMeMaybe{endpoints}`.
WireGuard 패킷(첫 바이트 1~4)과 매직으로 구분한다. DERP를 통해서도 보내야 홀펀칭 타이밍을
맞출 수 있다. `observedEndpoint`는 상대가 본 내 주소라 STUN 없이도 후보를 하나 더 준다.

**후보 수집.** 모든 NetworkInterface의 유니캐스트 주소(링크로컬 제외) + STUN 결과 + 상대가
알려준 `observedEndpoint`. IPv6 STUN은 hub가 IPv6를 가질 때만. UDP 소켓은 기본 41641,
실패 시 임의 포트.

**폴백 경로의 정리.** 데이터 평면의 폴백은 피어 간 TCP가 아니라 **hub 경유 릴레이**다.
피어 간 직접 TCP는 두지 않는다. 한쪽 TCP 포트가 밖에서 닿는 환경이면 직접 UDP도 대개 되고,
TCP 홀펀칭은 UDP보다 훨씬 덜 성공한다. Tailscale도 피어 간 TCP를 하지 않는다.

릴레이 비율에 대한 기대치도 적어둔다. 양쪽이 흔한 가정용 공유기 뒤면 UDP 홀펀칭은 대부분
성공한다(endpoint-independent 매핑). 릴레이로 남는 경우는 양쪽 대칭 NAT, 통신사 CGNAT, UDP를
막는 회사망이다. 따라서 직접 경로가 다수이고 릴레이는 소수라는 것이 설계의 전제다.
M4에서 이 비율을 실측해 로그로 남긴다.

**hub UDP 릴레이 (M4 실측 후 결정).** 릴레이 비율이 예상보다 높으면 TCP DERP의 두 약점이
커진다. 터널 안 TCP가 바깥 TCP 위에 얹혀 안팎 재전송이 간섭하는 것과, 한 TCP 스트림의
head-of-line 블로킹이다. 해법은 hub가 이미 열고 있는 UDP 소켓으로 WireGuard 패킷을 중계하는
것이다. 컨트롤 채널로 릴레이 세션 토큰을 받고 `[magic][8B sessionId][32B dstNodeKey][WG 패킷]`을
hub UDP로 보내면 hub가 목적지 세션으로 전달한다. 사실상 TURN이며 Tailscale도 최근 같은 것을
peer relay라는 이름으로 추가했다. 경로 우선순위는 직접 UDP → hub UDP 릴레이 → hub TCP 릴레이가
된다. TCP DERP는 UDP가 완전히 막힌 망을 위해 어차피 있어야 하므로 v1은 TCP DERP로 가고,
UDP 릴레이는 `PathSelector` 뒤에 가산으로 붙는다.

**v2 이후**: UPnP/NAT-PMP/PCP 포트 매핑, 다중 DERP.

---

## 10. Userspace 네트워크 스택 (`jailscale-netstack`)

**범용성의 핵심.** TUN 디바이스도 root도 필요 없다. 복호화된 IP 패킷을 순수 Java로
직접 처리하고, 사용자에게는 프록시와 포트포워드로 노출한다. Tailscale의
`--tun=userspace-networking --socks5-server=localhost:1055` 모드와 같은 구조이며, 차이는
Tailscale에서는 TUN을 못 만들 때의 예외 경로인 것이 우리에게는 기본 경로라는 점이다.
TUN이 없으면 OS는 `100.64.0.0/10`을 도달 불가 주소로 보므로, 애플리케이션이 netstack으로
들어올 문이 따로 있어야 한다.

```
        WireGuard transport  (평문 IP 패킷 in/out)
                 ▲ ▼
        ┌────────────────────┐
        │      IpStack       │  IPv4/IPv6 헤더 · 체크섬 · (프래그먼트는 드롭)
        └────────────────────┘
           │       │       │
        ┌──▼──┐ ┌──▼──┐ ┌──▼──┐
        │ICMP │ │ UDP │ │ TCP │  상태 머신 · 재전송 · 슬라이딩 윈도우
        └─────┘ └─────┘ └─────┘
                 ▲ ▼
        ┌────────────────────────────────────────────┐
        │  SOCKS5 + HTTP CONNECT  127.0.0.1:1055      │  아웃바운드 TCP (+UDP는 M5.5)
        │  로컬 포워드       -L 2222:laptop:22        │  아웃바운드 TCP/UDP
        │  리버스 포워드     -R 8080:127.0.0.1:8080   │  인바운드 TCP/UDP
        │  Java API          JailscaleSocketFactory   │  임베딩
        └────────────────────────────────────────────┘
```

**프래그먼트는 재조립하지 않는다.** 터널 MTU가 고정이고 TCP MSS를 우리가 클램프하므로
프래그먼트가 생기는 경우는 1240B를 넘는 UDP 데이터그램뿐이다. 수신한 프래그먼트는 버리고
카운터를 올린다. 송신 시 넘치는 UDP는 ICMP "fragmentation needed"를 로컬 소켓에 돌려주는
대신 드롭 + 로그. 단순함이 이긴다.

### 동시성 모델

netstack은 **단일 스레드 이벤트 루프**다. 스레드가 둘 이상 TCP 상태 머신을 만지는 순간
잠금 순서와 경합 버그가 따라오고, 그것이 userspace 스택 구현에서 가장 흔한 실패다.

- 패킷 경로(UDP 수신 → 복호 → `IpStack`)는 §13의 수신 스레드가 곧 netstack 스레드다.
  수신 스레드가 여럿이면 피어 해시로 netstack 인스턴스를 나눈다 (v1은 1개).
- 소켓 측(SOCKS5 연결, 포워드)은 연결당 virtual thread다. 이들은 netstack 상태를 직접 만지지
  않고 **연결당 송신 큐 / 수신 큐**로만 통신한다. virtual thread는 큐에서 블로킹한다.
- 타이머(RTO, delayed ACK, TIME_WAIT)는 §6의 단일 스케줄러가 netstack 스레드로 이벤트를
  넘긴다. 타이머 콜백이 상태를 직접 만지지 않는다.

### 버퍼 예산

윈도우 스케일링을 켜면 광고하는 윈도우가 실제 메모리다. 예산 없이는 RSS 30MB가 무너진다.

| 항목 | 기본값 |
|---|---|
| 연결당 수신 버퍼 | 256 KB (윈도우 스케일 3) |
| 연결당 송신 버퍼 | 256 KB |
| netstack 전체 상한 | 32 MB. 초과 시 새 연결은 광고 윈도우를 64 KB로 줄여 시작 |
| 아이들 RSS 목표 30 MB의 의미 | 연결이 없을 때의 수치. 연결당 최대 512 KB가 위에 얹힌다 |

수신 버퍼 자동 조정(autotuning)은 M5.5에서 실측 후 결정한다.

### TCP 범위

완전한 TCP를 다시 쓰는 건 큰 작업이므로 범위를 명시한다. 우리 스택의 유리한 점은
경로가 항상 WireGuard 터널이고 MTU가 고정이라는 것이다.

**v1 포함**

3-way 핸드셰이크, FIN/RST 종료, 순서 재조립, 누적 ACK, RTO 재전송(Karn/Jacobson),
슬라이딩 윈도우, **윈도우 스케일링 (RFC 7323)**, MSS 옵션, delayed ACK, Nagle off(프록시 용도),
fast retransmit / fast recovery (Reno), 무작위 ISN, TIME_WAIT(2×MSL, 상한 있는 테이블),
아웃바운드 임시 포트 할당(49152–65535).

윈도우 스케일링은 선택이 아니라 필수다. 없으면 수신 윈도우가 65535 B로 고정되어
처리량이 `윈도우 / RTT`에 못박힌다:

| RTT | 상한 |
|---|---|
| 20 ms (같은 리전, 직접 경로) | 26 Mbps |
| 50 ms (대륙 내 WAN) | 10.5 Mbps |
| 150 ms (대륙간 또는 DERP 경유) | 3.5 Mbps |

VPN에서 50 ms는 평범한 RTT다. 대역폭이 얼마든 10 Mbps에 걸린다는 뜻이다.
반면 구현은 SYN의 3바이트 옵션 + 시프트 값 하나 + 윈도우 필드 시프트 적용으로
40줄 수준이다. 비용 대비 효과가 압도적이다.

**M5.5로 연기: SACK (RFC 2018 / 6675)**

SACK 없이는 한 윈도우에서 N개를 잃을 때 fast retransmit이 RTT당 하나씩만 복구하므로
N RTT가 걸린다. 손실이 흩어져 있으면 차이가 작지만 **버스트 손실에서 무너진다.**
그리고 우리 아키텍처는 버스트 손실을 스스로 만든다 — §8의 DERP 릴레이가 data 큐
포화 시 패킷을 버린다. 즉 일반적인 경우보다 SACK의 가치가 높다.

그럼에도 연기하는 이유는 순수 분량이다(스코어보드 + 옵션 파싱 + 혼잡제어 연동으로
500줄 규모, M5는 이미 크다). **대신 재전송 큐를 처음부터 스코어보드 자료구조로
설계해서 SACK 추가가 재작성이 아니라 가산이 되게 한다.** 연기의 비용은 자료구조가
나중을 흡수할 수 있느냐로 결정된다.

**연기: 타임스탬프 / PAWS (RFC 7323)**

두 가지를 준다. (a) 재전송 세그먼트에서도 RTT 측정 — Karn 알고리즘으로 대체 가능하다.
(b) PAWS, 시퀀스 랩어라운드 방어 — 4 GiB 시퀀스 공간이 2×MSL(4분) 안에 도는 속도,
즉 **단일 연결 약 143 Mbps 이상**에서만 필요하다. 세그먼트당 12바이트 오버헤드는
MTU 1280에서 무시할 수 없다. 단일 연결이 그 속도에 도달하는 것이 관측되면 추가한다.

**M5.5**: SOCKS5 UDP ASSOCIATE, 수신 버퍼 autotuning.

**범위 밖**: ECN, CUBIC/BBR (Reno로 시작), 경로 MTU 탐색(터널 MTU가 고정이므로 불필요)

### 10.1 데몬과 CLI

`jailscale`은 하나의 바이너리지만 두 역할이다. `jailscale daemon`(또는 서비스 등록)이 상주하고,
나머지 서브커맨드는 데몬에 **로컬 IPC**로 요청한다.

- 전송: AF_UNIX 소켓. 위치는 `$XDG_RUNTIME_DIR/jailscale.sock`, 없으면
  `~/.config/jailscale/jailscale.sock` (0600). Windows도 AF_UNIX
  (`%LOCALAPPDATA%\jailscale\jailscale.sock`, 현재 사용자 ACL). 명명된 파이프는 쓰지 않는다 (§4).
- 프로토콜: 줄 단위 JSON 요청/응답 + 스트림 응답(로그, `up`의 진행 상황). hub 관리 IPC와
  같은 코덱.
- 명령: `up`, `down`, `status`, `invite`, `admin`, `ping <peer>`, `nc <host> <port>`, `netcheck`,
  `forward -L|-R ...`, `forward list|rm`, `leave`, `service install|uninstall`.
- `jailscale up`은 데몬이 없으면 데몬을 먼저 띄운다. 가입 진행, 승인 대기, 완료가 스트림
  응답으로 CLI에 흐른다.
- 콜드 스타트 50ms 목표는 이 CLI 왕복에 대한 것이다. 데몬 자체의 기동 시간은 사용자가 체감하지
  않는다.

### 사용성 관점

`jailscale up` 후 사용자가 해야 하는 일:

```bash
# 아무 설정 없이 바로: SOCKS5로 jailnet 접근
curl --socks5-hostname 127.0.0.1:1055 http://laptop.example.jail.net/

# 또는 익숙한 형태로 포트 매핑
jailscale forward -L 2222:laptop:22
ssh -p 2222 localhost

# ssh는 포트 매핑 없이도: ProxyCommand 한 줄을 ~/.ssh/config에 (jailscale up이 제안한다)
#   Host *.example.jail.net
#     ProxyCommand jailscale nc %h %p
ssh laptop.example.jail.net

# SOCKS를 모르는 도구를 위해 HTTP CONNECT 프록시도 같은 포트에서 받는다
HTTPS_PROXY=http://127.0.0.1:1055 some-tool https://laptop.example.jail.net/
```

`jailscale nc <host> <port>`는 stdin/stdout을 jailnet TCP 연결에 잇는 netcat이다. IPC로 데몬에
붙어 스트림을 중계하므로 데몬의 netstack을 그대로 쓴다. TUN이 없어서 `ssh laptop`이 바로 되지
않는 것이 이 설계의 가장 큰 사용성 비용인데, ProxyCommand가 그 비용의 대부분을 없앤다.
`127.0.0.1:1055`는 첫 바이트로 SOCKS5(0x05)와 HTTP CONNECT를 구분해 둘 다 받는다.

MagicDNS 이름(`laptop.example.jail.net`)은 SOCKS5의 hostname 모드에서
스택 내부가 직접 해석한다 — OS DNS 설정을 건드리지 않는다는 점이 중요하다.
(그게 root가 필요해지는 지점이므로.) `-L`의 목적지 호스트명도 데몬이 같은 표로 해석한다.

**SOCKS5 리스너의 접근 범위.** `127.0.0.1:1055`는 같은 머신의 모든 프로세스와 사용자에게 열려
있다. 단일 사용자 기기에서는 이것이 원하는 동작이다. 공유 서버에서는 `--socks unix:<path>`로
유닉스 소켓에 바인드해 파일 권한으로 제한할 수 있다. 사용자명/비밀번호 인증은 두지 않는다.
비밀번호가 설정 파일에 평문으로 놓이는 것보다 파일 권한이 낫다.

---

## 11. 가입 — 초대와 승인

IdP를 두지 않는다. 가입 권한은 **역량(capability)** 으로 전달한다. 초대 링크, 짧은 코드,
auth-key는 모두 "소지가 곧 권한"인 비밀값이고, hub는 그 값과 함께 온 NodeKey를 가입시킨다.
사용자의 이름은 초대에 실려 오거나 가입자가 스스로 적는다. 관리자가 언제든 바꿀 수 있다.

### 11.1 IdP를 빼는 이유

카카오 OAuth를 v2까지 유지했다가 뺐다. 근거는 설계서 안에 이미 있었다.

- IdP가 주는 것은 "이 사람이 누구인가"뿐이다. "들어와도 되는가"는 주지 않아서 초대·승인 큐를
  따로 만들어야 했다(v2 §11.4). 터널의 신원은 NodeKey, hub 인증은 hkey라 보안에도 관여하지
  않는다. 결국 IdP는 초대받은 사람에게 이름표를 붙이는 장치였다.
- 비용은 가장 컸다. hub 운영자 준비 6개 중 4개, 구현 1,000줄 규모의 보안 민감 코드, pairwise
  `sub` 마이그레이션, 선택 동의라 못 믿는 이메일, 그 IdP 계정이 없는 협업자 배제.
- 초대 링크에 이름을 실으면 이름표 문제가 그대로 풀린다. Tailscale의 auth-key, headscale의
  pre-auth key, Syncthing의 기기 승인이 모두 이 모델이며 IdP가 없다.

**잃는 것도 적는다.** 외부에서 검증된 신원이 없으므로 링크가 새면 다른 사람이 그 이름으로
들어온다. 대응은 1회용·짧은 TTL 기본값과 관리자 목록에서의 삭제다. 수십 명 이상 조직에서는
IdP가 다시 필요할 수 있으므로 §15에 OIDC 연동 슬롯을 남긴다.

### 11.2 초대 발급 — 어디서든 한 줄

초대는 **관리자만의 것이 아니다.** 기본 정책은 멤버 누구나 자기 노드에서 발급할 수 있다.
Slack의 초대와 같다. 발급자는 기록되고, 관리자는 `--invite-policy admins`로 좁힐 수 있다.

```
$ jailscale invite
초대를 만들었습니다 (1회, 24시간).
  링크:  https://hub.example.com/join/9f1cQ2…       ← 클립보드에 복사됨
  코드:  7F3K-92QX                                  ← 전화로 불러줄 때 (10분)

$ jailscale invite --user bob --uses 3 --ttl 7d      # 이름 고정, bob의 기기 3대
$ jailscale invite --self                            # 내 기기 하나 더
$ jailhub invite create ...                          # hub 셸에서도 같은 옵션
```

- **링크**는 128비트 토큰(base64url 22자). 기본 1회 · 24시간. 팀 채팅에 붙이는 용도.
- **코드**는 같은 초대의 별칭이다. Crockford base32 8자(40비트), **10분 · 1회**로 짧게 두고,
  hub는 IP당 분당 10회로 시도를 제한하며 실패가 쌓이면 코드를 폐기한다. 옆자리 동료나 전화
  너머에 불러주는 용도이며, 링크보다 약하므로 수명으로 보상한다.
- `--user`가 없으면 가입자가 이름을 적는다. `jailscale up`이 OS 사용자명을 기본값으로 묻는다.
- 클립보드 복사는 `pbcopy` / `xclip` / `clip.exe`를 `ProcessBuilder`로 부른다. 없으면 건너뛴다.
- 발급 요청은 IPC → 컨트롤 채널 `InviteCreate` → hub 순이다. hub에는 토큰의 해시만 남는다.

### 11.3 가입 흐름

```
$ jailscale up --invite https://hub.example.com/join/9f1cQ2…
 │        (또는 --hub hub.example.com --code 7F3K-92QX, 또는 --auth-key jk_…)
 ├─1. 링크에서 hub 호스트명을 뽑고 /v1/key로 hkey를 고정 (§7.1.1)
 ├─2. Noise 채널 개시, Hello로 버전 협상 (§7.2)
 ├─3. "hub.example.com 에 가입합니다. 이름 [wq]:"  ← 초대에 이름이 없을 때만 묻는다
 ├─4. RegisterRequest{ nodeKey, hostname, os, invite }
 ├─5. hub: 토큰 해시 대조 · 만료·잔여 횟수 확인 · 사용 횟수 차감 · 노드 ID·IP 할당
 └─6. RegisterResponse{ approved } → 곧바로 netmap push. 끝
```

브라우저가 열리지 않는다. 헤드리스 서버에서도 같은 명령이다. `/join/<token>`을 브라우저로
열면 사용 횟수를 소모하지 않고 CLI 설치 안내와 복사용 명령만 보여준다. 사람들은 링크를 일단
클릭한다.

**피싱.** 잔여 위협은 공격자가 자기 hub의 초대 링크를 뿌려 피해자를 엉뚱한 jailnet에 가입시키는
것이다. CLI는 3단계에서 어느 hub인지 출력하고 확인을 받는다. 가입해도 피해자의 로컬 서비스는
§12.4로 닫혀 있다.

### 11.4 두드리기와 승인 큐

초대가 없어도 hub 호스트명만 알면 문을 두드릴 수 있다.

```
$ jailscale up --hub hub.example.com
관리자 승인을 기다리는 중… (호스트명 wq-macbook, mkey:0J3B…)
```

hub는 `pending` 큐에 MachineKey·호스트명·OS·출발 IP만 기록한다. 관리자가 `/admin`이나
`jailhub node approve 0J3B… --user wq`로 승인하면 열려 있는 스트림으로 즉시 완료가 push된다.
Syncthing이 낯선 기기 ID를 승인하는 것과 같은 UX다. 두드리기는 무인증이므로 IP당 대기 항목
수를 제한하고, 큐는 24시간 뒤 비운다. 관리자가 두드리기를 원치 않으면 `--knock off`.

### 11.5 auth-key와 최초 부트스트랩

**auth-key**는 무인 등록용 초대다. CI·컨테이너·서버가 사람 없이 가입한다.

```
jailhub authkey create --owner alice                  # alice의 노드
jailhub authkey create --tag ci --uses 20 --ttl 7d    # 태그 노드. 사람 소유자 없음
jailscale up --hub hub.example.com --auth-key jk_…
```

`jk_` 프리픽스 + 128비트, hub에는 해시만. 태그 노드는 netmap `tags`에 표시되고 ACL 정책의
주어가 된다. 초대와 다른 점은 재사용 횟수가 크고 수명이 길며 이름을 묻지 않는 것뿐이다.

**최초 부트스트랩.** `jailhub serve`는 상태 디렉터리에 관리자가 없으면 콘솔에 첫 초대 링크를
찍는다. 그 링크로 가입한 첫 노드의 사용자가 관리자다. 관리자 추가는 `jailhub admin add <user>`
또는 `/admin`. 관리자 노드를 모두 잃으면 hub 셸에서 `jailhub admin login-link`로 복구한다.
셸 접근이 곧 최상위 권한이다.

**NodeKey 수명.** 기본 만료 없음. IdP가 있을 때의 키 만료는 "다시 로그인해 아직 그 사람임을
증명"하는 장치였는데, IdP가 없으면 재증명할 대상이 없다. 대신 관리자 폐기(`node remove`)와
선택적 `--node-key-ttl`을 둔다. 만료된 노드는 새 초대로 다시 가입하며 ID와 IP는 유지된다 (§5).

### 11.6 나중에 IdP를 붙인다면

요구가 관측되면 `RegisterRequest`에 `idToken` 필드를 추가하고 hub에 OIDC 검증기를 넣는다.
초대·코드·auth-key 경로는 그대로 두고, IdP는 "이름을 외부에서 검증한 초대"의 한 형태가 된다.
와이어 변경이 필드 하나라 지금 설계를 바꿀 이유가 없다.

## 12. 보안 모델 — 세 축의 분리와 hub 신뢰

세 가지가 자주 하나로 뭉뚱그려지지만 서로 직교하며, 어느 하나가 다른 하나를 보증하지 않는다.

| 축 | 질문 | 우리의 답 |
|---|---|---|
| **전송 보호 (E2E)** | 경로상의 누가 읽거나 위조할 수 있나 | 아무도. hub·DERP도 못 본다 |
| **인가 (ACL)** | 들어온 뒤 누가 누구에게 도달하나 | 기본 allow-all. 정책 지점은 M1부터 존재 |
| **멤버십** | 누가 jailnet에 들어오나 | 초대·auth-key·승인. **개방 가입 없음** |
| **피어 신원 바인딩** | "nkey X = alice의 laptop"을 누가 보증하나 | **hub.** hub 침해 시 이 보증이 깨진다 (§12.5) |

### 12.1 E2E는 인가를 대신하지 못한다

WireGuard의 종단간 암호화는 "경로상의 누구도 읽거나 위조할 수 없다"를 보장한다.
"상대가 내 기계에 접근해도 되는 사람인가"는 보장하지 않는다.

공격자가 jailnet에 들어오면 공격자는 중간자가 아니라 **엔드포인트**다. 그 상태에서 E2E는
공격자에게 기밀성과 무결성이 보장된 공격 채널을 제공할 뿐이다. 따라서
"모두 통신 가능하되 E2E로 보호된다"는 조합만으로는 안전 조건이 되지 않는다.

### 12.2 기본 ACL은 allow-all이다

들어온 멤버끼리는 전부 통신 가능한 것을 기본값으로 한다(Tailscale의 기본 ACL과 동일).
**신뢰 경계를 패킷 시점이 아니라 가입 시점에 두는** 모델이다.

다만 정책 평가 지점 자체는 M1부터 자리를 잡고 기본 규칙만 allow-all로 채운다.
나중에 좁히는 것이 기능 추가가 아니라 설정 변경이 되어야 하기 때문이다.

**netmap은 ACL로 필터링해서 배포한다.** 노드에게는 그 노드가 도달할 수 있는 피어만
보낸다. ACL이 allow-all이면 전체가 나가지만, 좁히는 순간 §12.3의 노출도 함께 좁아진다.

### 12.3 멤버십은 열 수 없다 — netmap이 곧 유출이다

인가나 서비스 노출 문제 이전에, **netmap 배포 자체가 정보 유출이다.** netmap은 모든
멤버에게 다른 모든 멤버의 호스트명, 사용자, jailnet IP, 온라인 여부, 그리고 STUN으로
발견된 **공인 엔드포인트 — 즉 집이나 사무실의 실제 IP와 포트**를 알려준다.

개방 가입이면 호스트명만 아는 누구나 조직 전원의 기기 목록과 실제 IP를 열람할 수 있다.
패킷을 한 개도 보내지 않고 가능하므로 E2E도 ACL도 이것을 막지 못한다.
따라서 §11의 역량 게이트는 선택이 아니다. 두드리기(§11.4)는 큐에 들어갈 뿐 netmap을 받지
않으므로 이 경계를 넘지 않는다.

Tailscale은 가입 경계를 조직(Workspace 도메인, GitHub org, Okta)이 그어준다. 우리는 IdP가
없으므로 초대 소지가 그 경계다. 멤버가 초대를 발급할 수 있는 기본 정책은 경계를 넓히는 것이
아니라 경계 안의 사람에게 확장 권한을 주는 것이며, 발급자가 기록된다.

### 12.4 userspace 설계가 공짜로 주는 것: 인바운드 기본 차단

이것은 명시적으로 기록해 둘 만한 보안 속성이다.

TUN 기반 VPN은 가입하는 순간 OS가 터널 트래픽을 로컬 리스닝 소켓으로 라우팅한다.
SSH, SMB, 데이터베이스 포트, 개발 서버가 인터넷에는 절대 열지 않을 것들이면서
"VPN 안이니까" 열려 있게 된다.

우리는 TUN 인터페이스가 없으므로 **OS가 터널 트래픽을 어디로도 보내지 않는다.**
사용자가 `jailscale forward -R 8080:127.0.0.1:8080`으로 명시적으로 노출하기 전까지
들어오는 연결이 도달할 수 있는 로컬 서비스는 존재하지 않는다.

즉 §10의 userspace 스택은 이식성 결정이면서 동시에 **기본 거부(default-deny) 인바운드**
정책이다. 적대적 노드가 jailnet에 들어와도 얻는 것이 §12.3의 메타데이터뿐이도록 만든다.

### 12.5 hub는 신뢰 대상이다 — 무엇을 할 수 있고 무엇을 못 하는가

정직하게 적어둔다. hub가 침해되면:

| hub가 할 수 없는 것 | hub가 할 수 있는 것 |
|---|---|
| 기존 터널의 트래픽 읽기·위조 (NodeKey 개인키가 없다) | **netmap에서 피어의 NodeKey를 공격자 키로 바꿔치기** → 이후 새 핸드셰이크는 공격자와 맺어져 MITM |
| 노드의 로컬 서비스 접근 (§12.4) | 임의 노드를 jailnet에 넣기, 승인 큐 우회 |
| 노드의 MachineKey·NodeKey 개인키 획득 (hub에 없다) | 누가 언제 누구와 얼마나 통신하는지 보기 (DERP 메타데이터) |
| | ACL을 allow-all로 바꾸기, 초대를 마음대로 발급 |

Tailscale은 첫 번째 항목을 tailnet lock(노드들이 서명 키로 netmap의 키 바인딩을 상호 서명)으로
막는다. v1은 이것을 하지 않는다. 대신 (a) hub의 개인키와 상태를 0600으로 지키고, (b) 노드는
피어의 NodeKey 변경을 로그에 남기며(`jailscale status --changes`), (c) 구현 여지를 §15에 남긴다.
self-host 단일 노드가 주 사용처이므로 "hub 운영자 = 조직"인 위협 모델이 대부분의 배포에 맞다.

**기타.** auth-key·초대 토큰·코드·관리 로그인 URL은 로그에 남기지 않는다. STUN은 무인증 UDP이므로
소스별 레이트리밋을 둔다(응답이 요청보다 크지 않아 증폭 가치는 없다). 인증되지 않은
TLS/Noise 핸드셰이크에는 IP별 레이트리밋. 데이터 평면 DoS 완화는 M4의 쿠키.

## 13. 스레딩 모델

| 역할 | 스레드 |
|---|---|
| UDP 수신 루프 = 복호 = netstack 이벤트 루프 | 플랫폼 스레드. **기본 1개**, `--rx-threads N`으로 확장 (피어 해시 분할) |
| 피어 타이머 · TCP 타이머 | 단일 `ScheduledExecutorService`. 콜백은 이벤트를 넘길 뿐 상태를 만지지 않는다 |
| 컨트롤/DERP 연결 (노드) | virtual thread 2 (read/write) |
| netstack 소켓 측 (SOCKS5, 포워드) | 연결당 virtual thread. 큐로만 netstack과 통신 |
| 로컬 IPC | 요청당 virtual thread |
| hub HTTP / DERP 세션 | 요청·세션당 virtual thread. DERP writer는 우선순위 큐 소비 |
| hub STUN | 플랫폼 스레드 1 |

핫패스(수신 → 복호 → netstack 주입)는 힙 할당이 0이 되도록 힙 배열 기반 버퍼 풀을
쓰고 virtual thread를 쓰지 않는다. 이유는 피닝이 아니라(Java 25는 synchronized 피닝이 없다)
지연 일관성이다. 스케줄러를 거치지 않는 경로가 가장 예측 가능하다. 나머지 전부는 virtual
thread로 자유롭게 쓴다.

수신 스레드가 1개인 것은 경량 원칙의 결과이기도 하다. 단일 스레드로도 수백 Mbps는 처리되며,
그 이상이 필요한 노드는 설정으로 늘린다.

---

## 14. 마일스톤

| # | 범위 | 완료 기준 |
|---|---|---|
| **M0** | 프로젝트 골격 · GraalVM 빌드 파이프라인 · `jailscale-crypto` · **경량 예산 측정 하네스** | RFC 7693/7748/8439 테스트 벡터 통과. `-Pnative`로 TLS 연결 + X25519 + ChaCha20을 도는 바이너리 생성, RSS·크기·처리량 수치를 CI에 기록하고 §4 게이트 활성화 |
| **M1** | Noise IK 핸드셰이크 · WireGuard transport · `PeerTransport` 경계 · ICMP · 정적 설정 · **wireguard-go 상호운용 테스트** | **두 프로세스가 정적 설정으로 100.64.x.x 간 ping 통과** ← 첫 목표. M1에는 데몬·IPC가 없으므로 `jailscale --static peers.json ping 100.64.0.2`처럼 단일 프로세스로 실행. CI에서 jailscale ↔ wireguard-go 양방향 핸드셰이크와 ping 통과 |
| **M2** | Coordinator: Noise 컨트롤 채널 · 자체 HTTP/1.1 서버·클라이언트 · **TLS 종단 + 내장 ACME** · 버전 협상 · 등록 · netmap · 초대 링크·코드 · 멤버 발급 · auth-key · 두드리기+승인 큐 · **로컬 IPC (노드·hub)** · `/admin` 최소 페이지(MachineKey 로그인) · hub 키 회전 | `jailscale invite`로 만든 링크로 다른 기기가 `jailscale up --invite`만으로 IP를 받는다. 코드로도 같다. 두드린 노드를 `/admin`에서 승인. `--auth-key`로 무인 등록. 키 회전 후 노드가 끊기지 않는다. Let's Encrypt 스테이징에서 발급·갱신 통과 |
| **M3** | DERP 릴레이 통합 · 우선순위 큐 | NAT 뒤 두 노드가 릴레이로 통신. data 큐 포화 시에도 netmap 푸시가 도달한다 |
| **M4** | STUN(2포트) · disco · 홀펀칭 · 경로 승격/강등 · keepalive · cookie | 직접 경로로 승격되는 것을 로그로 확인. 대칭 NAT 감지 시 승격을 시도하지 않는다. **릴레이 비율 실측** → UDP 릴레이 착수 여부 결정 |
| **M5** | userspace TCP(윈도우 스케일링 포함) · 이벤트 루프 · 버퍼 예산 · SOCKS5 · 포트포워드 | jailnet 너머로 `ssh`, `curl` 동작. 연결 100개에서 RSS가 예산 안 |
| **M5.5** | SACK · SOCKS5 UDP · 버퍼 autotuning · 혼잡제어 실측 튜닝 | 버스트 손실 하에서 처리량 회복 확인 |
| **M6** | MagicDNS · ACL · 릴리스 패키징 (5개 플랫폼 + fallback JAR) · 서비스 등록(systemd/launchd/Windows) · 참조 systemd 유닛 · Dockerfile(단일 이미지) · `ssh` ProxyCommand 안내 | `brew install` / 단일 바이너리 배포 |

**테스트 전략 (마일스톤 공통)**

- 파서(JSON, HTTP/1.1 요청·응답, DERP 프레이밍, TCP 옵션, disco)는 퍼징 대상이다. JDK 표준 라이브러리만 쓰므로
  Jazzer 등 외부 퍼저는 CI에서만 쓴다.
- 데이터 평면은 공개 테스트 벡터 + wireguard-go 상호운용으로 검증한다. 우리끼리만 통하는
  "표준 준수"는 인정하지 않는다.
- M2 이후 매 마일스톤 종료 시 §12의 표를 기준으로 위협 모델 재검토를 한 번 한다.

---

## 15. 미해결 / 추후 결정

- **Windows 지원 깊이** — netstack은 플랫폼 무관하지만 CLI의 브라우저 열기(`rundll32`),
  설정 경로, 파일 ACL, 서비스 등록은 분기가 필요하다. M6에서 다룬다.
- **혼잡제어 튜닝** — 터널 안 TCP가 바깥 TCP와 겹치는 이중 혼잡제어 문제.
  M5에서 실측 후 결정.
- **NodeKey 만료** — 기본 없음(§11.5). `--node-key-ttl`을 켠 배포에서 만료 전 안내 UX는 M2에서.
- **netmap 델타** — `seq`는 v1부터 있다. 델타 인코딩과 재동기화는 노드 수가 수백을 넘는
  배포가 관측되면.
- **피어 키 바인딩의 hub 독립 검증** — Tailscale tailnet lock 상당 (§12.5). 요구가 있으면.
- **다중 DERP / 다중 hub** — 단일 hub가 전제다. 지역 분산 릴레이는 별도 설계.
- **멀티 jailnet** — 하나의 hub가 여러 조직을 서빙할지. v1은 단일 jailnet.
- **IdP 연동 (OIDC)** — 수십 명 이상 조직에서 외부 검증 신원이 요구될 때. `RegisterRequest`에
  `idToken` 필드 하나를 더하는 형태 (§11.6). 초대 경로는 그대로 유지.
- **`--no-tls` 모드** — OAuth가 없으니 브라우저 경로는 `/join` 안내와 `/admin`뿐이다. 초대 링크에
  hkey 지문을 싣고 `/admin`을 관리자 노드의 IPC 터널로만 열면 인증서·ACME·80 포트가 전부
  사라진다. 443에서 비TLS를 막는 DPI가 있는 망에서 실패하므로 기본값은 못 된다. 요구가 있으면.
- **자체 ChaCha20-Poly1305** — native-image에서 JCE 처리량이 부족하면 (§4). M0 실측 후.
- **UPnP/NAT-PMP/PCP** — 대칭 NAT 뒤 노드의 직접 경로 확보. v2.
- **hub UDP 릴레이** — M4의 릴레이 비율 실측 후 결정 (§9). 우선순위는 이 목록에서 가장 높다.
- **ACME tls-alpn-01** — 80 포트를 열 수 없는 환경용. X.509 자체 서명 인증서 DER 생성이
  추가로 필요하다. 그때까지는 `--tls-cert`.
- **선택적 TUN 백엔드** — root가 *있는* 사용자를 위한 옵션. 범용성 원칙은 "root 불필요"이지
  "root 불허"가 아니다. netstack 대신 OS 라우팅을 쓰면 `ssh laptop`이 그냥 된다. v2.
