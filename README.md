# jailscale

로컬에서 도는 것을 인터넷에 HTTPS로 내놓는다. **중계하는 hub은 당신이 소유한다.**

```sh
# 노드(내 노트북) — hub 운영자가 준 초대 링크 한 줄로 가입
jailscale up --invite https://hub.example.com/join/TOKEN

# 로컬 3000번을 공개
jailscale open 3000 --name demo
# → https://demo.hub.example.com
```

방문자는 그 URL만 알면 된다. 노트북에는 **인터넷으로 열린 포트가 하나도 없다.** 포트포워딩도,
공인 IP도, TUN 장치도, root 권한도 필요 없다.

---

## 무엇이 다른가

localtunnel·ngrok·Cloudflare Tunnel·Tailscale Funnel·frp가 푸는 문제와 같다. 다른 것은
**누구를 믿어야 하는가**이다.

| | jailscale | ngrok · Cloudflare Tunnel | Tailscale Funnel | frp |
|---|---|---|---|---|
| 중계자 | 내 hub | 벤더 엣지 | 벤더 릴레이 | 내 서버 |
| TLS 종단 위치 | **노드** | 벤더 엣지 | 노드 | 직접 구성 |
| **중계자가 평문을 보는가** | **아니오** | **본다** | 아니오 | 구성에 따라 |
| 중계자가 키를 쥐는가 | 와일드카드 키 보유 | 보유 | 미보유 | 해당 없음 |
| TUN·root | 불필요 | 불필요 | TUN 필요 | 불필요 |
| 인증서 | 와일드카드 한 장, 자동 | 자동 | 자동 | 직접 |

**hub이 평문을 보지 못하는 것은 hub이 정직할 때의 이야기다.** 와일드카드 개인키는 hub에 있다.
침해된 hub은 이름을 공격자 노드로 재배정하고 그 키로 서명해 그 이름의 트래픽을 가로챌 수 있다.
무조건 성립하는 것은 사용자 도메인뿐이며, 그때는 키가 노드에만 있어 hub이 할 수 있는 일은
라우팅을 끊는 것뿐이다. 자세한 것은 [DESIGN.md §12.3](docs/DESIGN.md).

### 키는 hub에, TLS는 노드가

이 프로젝트에서 가장 특이한 부분이다.

```
방문자 ──ClientHello──► hub ──바이트 전달──► 노드 (TLS 종단)
                                              │  트랜스크립트 해시
                                              ├──서명 요청──► hub (조건 검사 후 서명)
방문자 ◄──────────────── hub ◄──바이트────── 노드
```

노드는 hub이 발급받은 와일드카드 **인증서**를 갖지만 **개인키는 없다.** TLS 1.3에서 개인키가
하는 일은 `CertificateVerify` 서명 한 번뿐이므로, 노드는 그 한 번만 hub에 부탁한다. hub은
트랜스크립트 해시만 보므로 평문을 복원할 수 없다. Cloudflare Keyless SSL과 같은 구조다.

hub은 아무 서명이나 해주지 않는다. 요청한 스트림이 **자기가 그 노드에 배달한 스트림**이고, 그
스트림의 SNI가 **그 노드에 배정된 이름**이며, 스트림당 4회와 노드당 속도 한도 안일 때만 서명한다.
그래서 노드가 침해되어도 공격자가 사칭할 수 있는 것은 원래 자기 이름뿐이다.

---

## 무엇이 보이고 무엇이 보이지 않는가

익명성은 상대에 따라 다르다. 뭉뚱그리면 위험하므로 나눠 적는다.

**방문자에게** 노드의 IP와 네트워크 위치는 드러나지 않는다. 방문자가 보는 주소는 hub의 것이다.
노드가 여는 리슨 포트는 0개이고, 방문자가 닿을 수 있는 것은 `jailscale open`으로 지정한
`host:port` 하나다. 같은 기기의 다른 서비스나 LAN은 보이지 않는다.

**hub 운영자에게는 숨겨지지 않는다.** 누가 언제 어느 이름에 얼마나 접속했는지 보인다. 트래픽
내용은 위에서 설명한 이유로 보이지 않지만, 그것도 hub이 정직할 때다. self-host라면 운영자는
보통 자기 자신이다. **남의 hub에 붙는다는 것은 그 사람을 신뢰한다는 뜻이다.**

가입만으로는 아무것도 열리지 않는다. `jailscale open`을 친 포트만, 그 명령을 친 동안만 열린다.

---

## 크기와 속도

형용사 대신 측정값을 둔다. 전부 `./measure.sh --check`로 재현되며, 예산 게이트가 회귀를 막는다.

| 측정 | 값 | 예산 |
|---|---|---|
| 바이너리 크기 | jailhub 25.0 / jailscale 25.2 MiB | ≤ 30 MiB |
| 아이들 RSS | hub 24.9 / 노드 24.7 MB | ≤ 30 / 28 MB |
| 방문자 1,000명 동시 접속 | 1,000/1,000 성공, 0.5초 | — |
| 부하 직후 RSS | hub 75.2 / 노드 97.0 MB | ≤ 128 MB (목표는 더 낮다, §15) |
| CLI 콜드 스타트 | 6.8 ms | ≤ 50 ms |

측정 환경은 arm64 macOS의 네이티브 빌드다. 서버를 서울 GCP e2-micro에 두고 실제로 재보면
인터넷 왕복이 0.06초였다.

**서드파티 런타임 의존성은 0개다.** JSON 파서, HTTP/1.1, mux, ACME 클라이언트, DNS 응답기를
직접 갖고 있다. 암호는 JDK의 것(X25519, ChaCha20-Poly1305)을 쓰고, Noise가 요구하는
BLAKE2s·HMAC·HKDF만 직접 구현한다. 공급망 표면이 0이라는 뜻이고, 저장소에 커밋된 바이너리
파일도 없다. 이유는 [DESIGN.md §4](docs/DESIGN.md)에 항목별로 적혀 있다.

---

## 설치

릴리스에서 플랫폼 바이너리를 받는다. linux/macOS × amd64/arm64와 windows-amd64를 제공하고,
그 밖의 환경을 위해 JVM 25용 fallback JAR(`jailscale.jar`, `jailhub.jar`)도 함께 올린다.
런타임을 따로 설치할 필요는 없다.

### hub 세우기

운영자가 준비할 것은 **DNS 레코드 셋과 포트 셋**이 전부다.

```
hub.example.com.                  A   203.0.113.10      ← 프록시 없이 직접
*.hub.example.com.                A   203.0.113.10
_acme-challenge.hub.example.com.  NS  hub.example.com.
```

```sh
jailhub serve --base-url https://hub.example.com --acme-email you@example.com
```

hub이 `_acme-challenge` 이름의 권한 DNS 서버가 되어 스스로 dns-01 챌린지에 답하고, 와일드카드
한 장을 받는다. 이름마다 인증서를 받지 않으므로 **새 이름은 0초에 열린다.** 필요한 포트는
TCP 443과 DNS 53(UDP·TCP)이며, 80은 사용자 도메인 기능을 쓸 때만 필요하다.

Cloudflare를 쓴다면 A 레코드 둘은 **회색 구름(DNS only)** 이어야 한다. 주황 구름은 SNI 통과를
깨뜨리며, hub의 자가 진단이 기동 시 이를 잡아낸다.

### 자기 도메인 쓰기

```sh
jailscale open 3000 --domain app.example.com
```

`app.example.com`을 hub으로 CNAME하면, 노드가 **자기 키로** HTTP-01 챌린지를 치러 인증서를 받는다.
이 경우 hub은 순수 통과이고 키도 인증서도 노드에만 있다.

---

## 그 밖에

`jailscale open 22 --tcp`로 TLS 없는 raw TCP/UDP 포트를 공개할 수 있다. `--gate`를 붙이면 방문
링크를 가진 사람만 열 수 있다. `jailhub serve --takeover`는 진행 중인 다운로드를 끊지 않고 hub
프로세스를 교체한다. nginx `stream`이나 HAProxy 뒤에 둘 수 있고 참조 설정이 `deploy/`에 있다.

---

## 한계

- **hub은 단일 프로세스·단일 호스트다.** 능동-능동 다중화는 없다. 재시작은 5초 안에 끝나고
  무중단 교체가 있지만, 호스트 자체를 잃으면 그동안 서비스가 멈춘다.
- **hub 앞에 TLS를 종단하는 리버스 프록시를 둘 수 없다.** SNI 통과가 필요하기 때문이다. nginx
  `stream`이나 HAProxy `mode tcp`처럼 바이트만 넘기는 4계층 프록시는 된다.
- **hub은 신뢰 대상이다.** 위의 위협 모델을 읽고 판단할 것.
- **Windows에서 드물게 재접속이 필요하다.** JDK 25의 가상 스레드 관련 버그이며 jailscale 코드와
  무관하다. 재현기와 측정이 [docs/windows-virtual-thread-stall/](docs/windows-virtual-thread-stall/)에 있다.
- 노드 아이들 RSS 20 MB 목표를 아직 못 맞췄다(현재 24.7 MB). 대부분 JSSE의 이미지 힙이다.

---

## 문서

설계 전문은 [docs/DESIGN.md](docs/DESIGN.md)에 있다. 프로토콜, 위협 모델, 예산, 마일스톤별
실측이 모두 그 문서에 있고, 이 README는 그 요약이다.

## 라이선스

아직 정해지지 않았다. 저장소에 `LICENSE` 파일이 없으므로 현재로서는 전권 보유 상태다.
