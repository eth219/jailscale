# deploy/

운영자용 참조 파일. 설계 근거는 `docs/DESIGN.md` §6.3, §7.7, §9.6, §14.

| 파일 | 용도 |
|---|---|
| `jailhub.service` | hub systemd 유닛. `systemctl reload jailhub`가 `jailhub serve --takeover`(무중단 교체)로 연결됨 |
| `Dockerfile` | hub 컨테이너 (GraalVM native → distroless, ~30 MB) |
| `nginx-stream.conf` | 이미 nginx가 443을 쥔 서버에 hub를 얹을 때. `ssl_preread` SNI 라우팅 + PROXY 헤더 |
| `haproxy.cfg` | 같은 것을 HAProxy로. `send-proxy-v2` |
| `homebrew/jailscale.rb` | tap용 formula 템플릿 |

노드 쪽 서비스 등록은 파일이 아니라 명령이다: `jailscale service install` (macOS launchd, Linux systemd --user, Windows 로그온 작업).

프록시 뒤에 둘 때 hub는 반드시 `--proxy-protocol`과 함께 루프백에 리슨하거나 `--trusted-proxy <cidr>`를 줘야 한다. 그렇지 않으면 방문자 주소를 아무나 위조할 수 있으므로 hub가 기동을 거부한다.
