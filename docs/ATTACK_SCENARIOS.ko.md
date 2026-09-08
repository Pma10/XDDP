# L3/L4/L7 공격 시나리오와 방어 전략

작성 기준: 2026-09-08 저장소 코드. 이 문서는 운영 및 후속 개발 계획이며,
실서버 부하 시험 결과나 공격 처리 용량 인증이 아니다. 후속 구현에서 선택적
중계/백엔드 보호, status 준비 캐시, 자동 승격 조건, conntrack 관측을 추가했다.
격리 loopback 기능 시험을 수행하며 운영 서비스/방화벽/제한값은 변경하지 않는다.
실제 설정은 [추가 방어 설정](RESILIENCE.ko.md)을 따른다.

## 목표와 우선 조건

우선순위는 기존 플레이어의 게임 진행 유지, 정상 신규 로그인 유지,
서버 목록 응답 유지 순서다. 과부하 시 목록 조회를 먼저 제한할 수 있지만,
클라이언트는 목록이 보이지 않으면 접속 불가로 생각할 수 있으므로 이를 측정한다.

방어 경로는 앞단 방어 업체 → XDP → Linux TCP/방화벽 → XDDP 게이트 →
PROXY v2 수신 백엔드 → 인증/BotSentry/게임 서버다.

- 실제 플레이어 IP가 게이트와 백엔드 양쪽에서 구분되는지 먼저 검증한다.
  XDDP의 PROXY v2 송신은 게이트가 본 TCP peer를 전달한다. 앞단 업체가
  주소를 변환하면 송신 옵션만으로 원래 IP를 복원하지 못한다.
  현재 게이트에는 앞단에서 들어오는 PROXY 헤더 수신 기능이 없다.
- 같은 호스트의 PROXY 수신 백엔드는 loopback에 바인딩한다. 다른 호스트면
  게이트만 접근할 수 있는 네트워크/방화벽 경계를 사용한다. IPv6도 확인한다.
- 25566 직접 접속, 별도 공인 IP, AAAA 레코드 등 게이트 우회 경로를 확인한다.
- 정상 로그인 형식의 봇은 BotSentry에 맡기되, 통과 전까지 사용하는 인증
  슬롯/CPU/메모리와 최대 인증 대기 시간은 별도로 제한한다.

## 시나리오별 전략

| 시나리오 | 먼저 고갈되는 자원/관측 | 방어 전략 | 현재 구현과 남은 한계 |
| --- | --- | --- | --- |
| L3: 대역폭을 채우는 UDP/반사 트래픽 | 회선 수신 bps, 앞단 손실, NIC drop | 앞단에서 회선 유입 전에 정화. 사용하지 않는 UDP 목적 포트만 명시적으로 차단 | XDP에 명시적 포트 차단 기능은 있으나 기본 목록은 비어 있음. 로컬 DROP은 이미 소모한 회선 대역폭을 돌려주지 못함 |
| L3: 작은 패킷으로 높은 PPS | RX queue, softirq CPU, softnet drop | 앞단 PPS 방어와 XDP의 저비용 검사. 실제 NIC/가상 NIC에서 처리 한계 측정 | 상태 생성 없는 XDP 경로. 모든 정상 형식의 패킷을 걸러내는 기능은 없음 |
| L3: 조각화/IPv6 확장 헤더 | fragment 재조립 비용, IPv6 deferred | 앞단/호스트 정책으로 처리. IPv4와 IPv6 경로를 따로 시험 | TCP fragment 차단은 선택 사항이며 주소상의 다른 TCP 서비스에도 영향. IPv6 확장 경로는 주로 커널 위임 |
| L3/L4: 잘못된 길이/헤더 | malformed 후보, 커널 drop | 경계와 구조 검사 후 커널 검증 | XDP 기본 IP 파싱 오류는 owned 목적지 확인 전에도 후보 DROP이 될 수 있음. 적용 인터페이스 전체 영향 검증 필요. 체크섬/세부 TCP 옵션은 Linux 담당 |
| L4: SYN만 대량 전송 | SYN_RECV, syncookie, backlog, SYN/s | 앞단 SYN 검증, Linux SYN cookie 설정 확인, 필요 시 XDP SYN 예산 | XDP SYN 예산은 CPU별이고 기본 0. CPU/RX 분배 변경 시 실효 한도가 달라짐. SYN proxy는 미구현 |
| L4: ACK/RST/PSH 대량 전송 | softirq, NIC PPS, 재전송/지터 | 앞단의 TCP 검증과 Linux 상태 검증. 정상 ACK/PSH 일괄 PPS 제한은 피함 | XDDP는 정상 헤더 모양만으로 기존 TCP 세션 소속을 증명하지 못함. stateless XDP의 중요한 잔여 위험 |
| L4/L7: TCP 연결만 하고 유지 | accepts/s, active_prelogin, FD | 전역 자원 상한, 최초 데이터/절대 handshake 제한 시간, 필요 시 출발지별 미완료 연결 상한 | 미완료 연결 제한과 시간 제한 구현. 분산 소스는 전체 prelogin 풀을 계속 점유할 수 있어 앞단 신규 연결 검증도 필요 |
| L7: 바이트를 조금씩 보내 유지 | progress/handshake timeout, prelogin 점유 | 진행 제한 시간과 별개인 절대 단계 제한 시간 유지 | 구현됨. 지연/손실 높은 정상 클라이언트로 시간 제한 오탐 확인 |
| L7: 무작위 바이트/과대 길이 | invalid_varint, oversized_packet, handshake_invalid | 길이를 할당 전에 검사하고 해당 연결 종료. 초기 총 바이트 상한 | 구현됨. 연결 자체의 TCP 처리 비용은 앞단/accept 방어 필요 |
| L7: 정상 Handshake 뒤 Login Start 없음 | handshake 성공, login 시작 정체, prelogin 증가 | Login Start 완료 전 백엔드 연결 금지, login 제한 시간 | 구현됨. handshake 성공 건수를 실제 접속 성공으로 오인하지 않음 |
| L7: status 조회 폭주/핑 미전송 | status/s, active_status, 게이트 CPU | 캐시 응답, 별도 status 예산/동시 연결 상한, 상태 요청/ping 시간 제한 | 구현됨. 캐시 갱신은 요청 수와 독립. 모든 조회가 global accept 자원은 공유하므로 로그인 완전 예약은 아님 |
| L7: 정상 Login Start 뒤 인증 미완료 | admitted/backend 점유, 인증 대기, JVM CPU | 백엔드 인증 단계 제한 시간/동시량, BotSentry, 전역 login 예산 | 게이트는 Login Start 이후 불투명 중계. admitted는 인증 완료가 아니며 이후 무응답을 게이트가 인증 상태로 구분하지 못함 |
| L7: 한 연결의 지속적인 대용량 업로드 | monitored_upload_bytes, budget exceeded, JVM CPU | 충분한 burst를 둔 연결별 업로드 예산. 초과 연결만 종료 | 선택 기능 구현, 기본 비활성. 수신 회선/커널 비용은 이미 발생. 모드/observe와 독립 |
| L7: 많은 연결이 각각 업로드 한도 이하 | 전체 대역폭/CPU, admitted 수 | 앞단 총량, 입장률/동시량, 백엔드 작업별 제한 | 연결별 예산만으로 해결 불가. 전체 중계량 관측과 새 입장 제한이 필요. 모든 플레이어 공유 byte bucket은 피함 |
| L7: 작은 입력으로 비싼 작업/압축 해제 유발 | JVM CPU, MSPT, GC, 플러그인 작업량 | 백엔드 패킷/압축 해제 크기/작업별 예산과 취약점 수정 | 암호화·압축 뒤 패킷을 게이트가 의미 분석하지 않음. BotSentry가 모든 로그인 이후 공격을 막는다고 가정하지 않음 |
| 혼합: SYN + status + 로그인 폭주 | 서로 다른 자원이 동시에 포화 | 앞단 PPS/SYN, 게이트 status 분리, 인증 동시량을 동시에 조정 | 단일 공격 유형 판정이나 단일 총 PPS 임계값으로 처리하지 않음 |
| 운영: 백엔드 장애 뒤 정상 재접속 폭주 | backend 실패, 재시도, 정상 유저 실패 | 백엔드 복구, 정상 burst 보존, 연결 실패를 사용자 악성 점수에 더하지 않음 | 서버 측 거절과 백엔드 실패는 churn 점수에서 제외됨. 영구/광역 IP 차단 금지 |
| 운영: 공격 중 컨트롤러/게이트 장애 | 갱신 지연, generation, 서비스 상태 | lease 만료 관측, 알림, 계획된 복구 | 컨트롤러 만료는 관찰/PASS로 복귀. 게이트 프로세스 종료는 기존 중계 연결을 끊음 |

용량 공격은 회선과 CPU를 각각 소모할 수 있다. 로컬 처리보다 앞단에서
흡수해야 하는 이유는 [Cloudflare의 L3/L4 분석](https://blog.cloudflare.com/how-cloudflare-auto-mitigated-world-record-3-8-tbps-ddos-attack/)을 참고한다.
SYN cookie는 backlog 초과 시의 보호 수단이며 정상 부하를 수용하도록 용량을
조정하는 일을 대신하지 않는다. [Linux TCP 설정 문서](https://kernel.org/doc/html/latest/networking/ip-sysctl.html).

## 정상 유저 피해를 줄이는 운영 순서

1. 실 IP 전달, 백엔드 비공개, IPv6 경로를 먼저 검증한다.
2. 정상 피크/공유 NAT/서버 재시작 후 재접속을 포함한 기준 데이터를 수집한다.
3. 초기 길이/시간/메모리 상한을 유지하며 status와 login을 분리한다.
4. 정상 동시 접속량을 수용하는 범위에서 prelogin과 backend 상한을 정한다.
5. 측정한 지속률보다 여유 있는 입장률을 선택하고 정상 burst를 별도로 허용한다.
6. 한 IP의 행동 때문에 prefix 전체를 먼저 제한하지 않는다. IP는 플레이어 식별자가 아니다.
7. 공격 시 status 비용을 먼저 줄이고, 인증/로그인 동시량과 신규 입장을 다음에 제한한다.
8. EMERGENCY는 신규 정상 접속도 모두 거부하는 최후 수단이다. 기존 중계는
   모드 변경만으로 끊지 않지만, source ACL 변경은 XDP에서 기존 패킷도 차단할 수 있다.

정상 상한과 서버의 안전 처리 용량 사이에 여유가 없는 경우 설정값만으로
정상 로그인 성공률을 보장할 수 없다. 앞단 검증 강화 또는 용량 확충이 필요하다.
특정 배수나 고정 PPS/초당 로그인 수를 이 문서에서 실서버 권장값으로 사용하지 않는다.

## 관측과 자동 대응 개선안

컨트롤러는 기본적으로 설정된 신호 중 하나가 enter 임계값을 넘으면 연속 샘플/
cooldown 조건에 따라 승격한다. 추가된 required_signals를 사용하면 해당
모드에 여러 신호의 동시 충족을 요구할 수 있다. 자동 EMERGENCY는 명시적으로
허용해야 한다. 그 외에는 한 번에 높은 모드로 올라갈 수도 있다.
현재 샘플 thresholds는 비어 있으므로 자동 승격이 꺼져 있다.

다음은 운영 조건 설계다. 현재 구현은 required_signals와 게이트 자원/실패 및
conntrack 신호를 제공하며, CPU/JVM/인증 완료 신호 수집은 별도 개발 대상이다.

- SYN 증가와 backlog/softirq 압박을 함께 보아 SYN 대응을 선택한다.
- status 증가와 게이트 CPU/동시량 압박을 함께 보아 status 예산만 조정한다.
- 로그인 증가와 인증 대기/실패, JVM 압박을 함께 보아 새 로그인 예산을 조정한다.
- 여러 샘플의 지속적인 압박으로 승격하고, 정상화는 낮은 exit 기준으로 천천히 수행한다.
- EMERGENCY는 운영자 확인 또는 검증된 심각한 자원 부족 조건으로 제한한다.
- 지표가 없거나 오래되었을 때 정상이라고 판단하지 않고 관측 장애로 표시한다.

주의할 현행 지표:

- `pps`/`bps`는 XDP 진입 수신량 기반으로 다른 서비스와 차단 전 트래픽도 포함한다.
  공격 차단에 성공해도 이 값이 높을 수 있으므로 단독 EMERGENCY 트리거는 부적절하다.
- 컨트롤러 `bps`는 bit/s, `upload.bytes_per_second`는 byte/s다.
- `handshake_ok`에는 상태 조회도 들어간다. `login_starts`와 `admitted_clients`도
  인증 완료/실제 플레이어 수가 아니다. 백엔드 로그인 성공 지표를 추가 수집한다.
- `new_ip_entries`는 테이블 삽입 수이지 완벽한 고유 IP 수가 아니다.
- `status_capacity_limited`, `active_prelogin`, `backend_connect_failures`, FD/RSS,
  CPU/softirq, NIC drop, TCP ListenOverflows/ListenDrops, MSPT/GC를 함께 확인한다.

## 후속 개발 우선순위

| 순서 | 작업 | 이유/완료 기준 |
| --- | --- | --- |
| P0 운영 | PROXY v2 양쪽 활성화 및 백엔드 비공개 확인 | 실제 외부 유저 두 명의 IP가 백엔드에서도 구분됨. 외부에서 백엔드 직접 접근 불가 |
| P0 운영 | 관찰/실제 차단 상태와 유효 제한값 확인 | observe=true는 XDP 차단 안 함. gate 자원/구조 상한은 작동. rate=0은 속도 제한 안 함. upload.enforce는 독립 |
| P1 구현됨 | status JSON 렌더링을 갱신 시점으로 이동 | 고정 prefix/suffix에 숫자만 삽입. 요청자가 캐시 항목/백엔드 조회를 늘리지 못함. 호스트/프로토콜별 MOTD 다중 캐시는 별도 |
| P1 운영 | 인증 전 자원 제한과 실제 게임 지연 측정 | BotSentry 처리 중에도 JVM과 인증 대기 슬롯이 상한 내에 머무름 |
| P1 구현됨/설정 필요 | required_signals와 자동 EMERGENCY 명시 허용 | 운영자가 실제 자원 신호의 임계값을 설정해야 함. CPU/JVM 기반 정책은 별도 |
| P2 검토 | 앞단 PROXY 수신 필요성 판별 | 업체가 원본 IP를 TCP peer로 보존하지 않을 때만 검토. 신뢰된 peer 검증, 파싱 길이/시간 상한, spoof 헤더 거절 필요 |
| P2 검토 | 로컬 SYN proxy/추가 상태 검증 | 앞단 잔여 SYN/ACK 때문에 실제 병목이 확인될 때 설계. TCP 옵션/재전송/PMTU/비대칭 경로 시험을 먼저 정의 |

## 검증 시나리오와 합격 기준

운영 서버를 대상으로 공격을 발생시키지 않는다. 소유한 격리 테스트 환경에서
정상 유저 세션을 유지한 채 하나의 변수씩 늘리고, 단일 시나리오를 통과한 후
혼합 시나리오를 수행한다. 각 실행 전에 최대 접속 수, byte/s, 지속 시간과
CPU/메모리/지연 중단 기준을 해당 테스트 호스트 용량에 맞춰 기록한다.

- 정상군: 1.8 및 실제 서비스의 최신 클라이언트, ViaVersion, RGB MOTD,
  상태 ping, 로그인, 이동/전투, 모드/플러그인 데이터, 대형 NAT 동시 재접속.
- 네트워크군: 짧은 지연부터 실제 지원할 고지연·패킷 손실·재전송까지,
  TCP 분할/합쳐짐, MTU/PMTU, IPv4/IPv6 지원 범위를 검증한다.
- L3/L4군: 잘못된 구조와 정상 패킷을 섞어 false drop을 확인한다.
  SYN, ACK, 분산 연결 유지 각각에서 커널 및 게이트 병목을 구분한다.
- L7군: 침묵/느린 전송/잘못된 길이/status 폭주/미완료 로그인/단일 업로드/
  여러 저속 업로드를 구분하고 단계별 timeout 및 자원 회수를 확인한다.
- 장애군: 캐시 백엔드 정지, 컨트롤러 lease 만료, 관측 누락,
  백엔드 재시작 뒤 정상 재접속을 검증한다. 게이트 종료에 의한 세션 단절은
  무중단으로 보고하지 않는다.

합격 판정은 드롭 수가 아니라 정상 신규 로그인 성공률, 기존 유저 disconnect,
게임 동작 지연 p95/p99, MSPT/GC, FD/RSS 상한, 공격 종료 후 회복 시간으로 한다.
무부하와 같은 정상 부하의 대조군, 방어 관찰 모드, 방어 적용 모드를 비교한다.
실제 게임 RTT와 캐시가 즉시 답하는 서버 목록 ping을 구분한다.

기존 기능 회귀 검증은 `tests/test_xdp.py`, `tests/gate_integration.py`,
`tests/gate_abuse_integration.py`, `tests/gate_fairness_integration.py`,
`tests/test_controller.py`를 활용한다. 이 테스트들의 통과가 앞단 장비,
실제 NIC, ViaVersion/BotSentry 구성, 생산 환경 용량을 검증한 것은 아니다.

## 코드 근거

- `xdp/xdp_ddos.bpf.c`, `xdp/parse.h`: XDP 검사, 적용 범위, SYN 예산, ACL.
- `gate/src/main.rs`, `gate/src/protocol.rs`: 단계별 검사/시간/동시량과 admission.
- `gate/src/cache.rs`: 단일 폴링, 캐시 TTL, 클라이언트 응답 렌더링.
- `gate/src/relay.rs`: 선택적 연결별 업로드 예산, 불투명 중계.
- `gate/src/limiter.rs`: 출발지/전역 예산 및 churn.
- `controller/core.py`: 현행 자동 승격/복구 판정 및 지표 단위.
- `config/controller.json`, `config/gate.json`: 저장소 기본값. 설치된 서버 설정은 별도 확인 대상.
