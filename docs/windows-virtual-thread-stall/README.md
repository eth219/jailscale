# Windows + 가상 스레드 + 양방향 루프백에서 읽기가 깨어나지 않는 문제

`MuxSessionTest.largeTransferRespectsFlowControl`이 Windows CI에서만 간헐적으로 30초 타임아웃에
걸렸다. 원인을 좁힌 결과 **jailscale 코드와 무관한 JDK 문제**였다. `SockLoop.java`는 의존성 없이
그 현상만 남긴 재현기다 (`java.base`만 쓴다).

```sh
javac -d out SockLoop.java
java -cp out SockLoop <반복> <건당 타임아웃 s> <전체 예산 s> <virtual|platform> <uni|bidi>
```

## 측정 (GitHub Actions, Liberica NIK 25.0.4, 4코어)

| 조건 | 멈춤 |
|---|---|
| windows-2025, bidi, **virtual** | 152회 중 **60** (39.5%) |
| windows-2025, bidi, platform | 5,000회 중 0 |
| windows-2025, uni, virtual | 5,000회 중 0 |
| ubuntu-24.04, bidi, virtual | 5,000회 중 0 |
| ubuntu-24.04, bidi, platform | 5,000회 중 0 |

세 가지가 모두 있어야 터진다. **Windows, 가상 스레드, 양방향 트래픽.** 하나라도 빼면 나오지
않는다. 참고로 같은 조건에서 우리 `MuxSession`을 거치면 3,000회 중 55회(1.8%)로, 재현기보다
오히려 낮다. Noise 암호화와 프레임 처리가 타이밍을 바꾸기 때문이지 우리 쪽 결함이 아니다.

## 무엇이 멈추는가

쓰는 쪽은 송신 버퍼가 차서 park되고, 읽는 쪽은 프레임 길이를 기다리며 park된 채 깨어나지
않는다. 루프백 연결 하나에서 동시에 성립할 수 없는 조합이라, Windows의 `wepoll` 기반 폴러가
읽기 준비 신호를 잃는 것으로 보인다. 플랫폼 스레드는 OS에서 직접 블록하므로 이 경로를 타지
않는다.

## jailscale에 대한 영향

코드로 고칠 수 있는 것이 아니다. 감지하고 복구하는 안전망은 이미 있다. hub(`NodeSession`)과
노드(`HubClient`) 모두 mux 소켓에 60초 읽기 타임아웃을 걸고 `MuxSession`이 25초마다 KEEPALIVE를
보내므로, 실제로 이 일이 나면 `peer idle too long`으로 세션이 닫히고 노드가 재접속한다. 그 연결의
방문자는 최대 60초를 잃고 그 뒤 회복된다.

CI에서는 `MuxSessionTest`가 Windows 실행의 1~2%에서 실패한다. 테스트를 끄거나 재시도로 덮지
않는다. 실패하면 이 문서를 보면 된다.
