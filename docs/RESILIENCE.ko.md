# 추가 방어 설정 및 적용

실 IP 전달이 정상인 상태를 기준으로 한다. 이 기능들은 저장소에서 구현했으며,
실서버에 자동 배포하거나 제한값을 자동 설정하지 않는다. 설치 프로그램은
기존 `/etc/xddp/*.json`을 보존한다.

## 기본적으로 적용되는 변경

- 상태 조회마다 JSON을 복제/직렬화하던 작업을 캐시 갱신 시점으로 옮긴다.
  공격자가 프로토콜 번호를 계속 바꾸어도 캐시 항목과 백엔드 폴링이 늘지 않는다.
- 자동 EMERGENCY는 명시적으로 `adaptive.allow_emergency=true`를 설정해야 한다.
  누락된 기존 설정도 false로 처리한다. 수동 EMERGENCY는 그대로 사용 가능하다.
- conntrack을 사용할 경우 점유율을 읽어 상태 신호에 포함한다. 커널 설정은 변경하지 않는다.

## 선택적 보호 설정

아래는 검증을 시작할 때 사용할 예시이며, 측정된 운영 권장값은 아니다.
시간 제한과 동시량은 공유 NAT, 불안정한 회선, 모드 및 플러그인 전송으로 검증한다.
0이면 새 제한은 꺼져 있다. 기존 `timeouts` 객체에 필요한 필드만 추가하고,
`backend_protection`은 게이트 JSON 최상위에 추가한다. 주소/PROXY 설정은 유지한다.

```json
"backend_protection": {
  "max_connecting": 32,
  "failure_threshold": 8,
  "cooldown_ms": 1000,
  "attempts": {"per_second": 2, "burst": 8}
}
```

`max_connecting`은 `limits.backend` 이하로 정한다. 이는 연결 및 초기 송신 중인
동시 시도 제한이며, 초당 접속률이나 이미 접속한 플레이어 수 제한이 아니다.
연속 실패 때 대기열을 만들지 않고 새 연결을 종료하며, 대기 후 한 연결로 복구를 확인한다.
정상 TCP+초기 송신 이후의 BotSentry 거절은 장애로 계산하지 않는다.
그러한 반복 접속의 속도 제한은 기존 `limits.global.login`의 측정된 rate/burst로 설정한다.
`attempts`를 활성화하면 성공/실패와 무관하게 백엔드 연결 시도 자체를 전역으로
제한한다. 공유 NAT에서 정상 재접속을 수용할 수 있도록 burst를 실제 피크보다 높게
잡고, 기본 0/0은 비활성이다. 이 제한은 게이트 인스턴스 단위이며 IP별 식별이 아니다.

기존 `timeouts`에 추가할 필드 예시:

```json
"relay_stall_ms": 30000,
"half_close_ms": 30000,
"client_idle_ms": 0
```

아무 데이터도 없는 정상 대기는 stall이 아니다. 보낼 데이터가 있는데 실제 쓰기가
진행되지 않는 상태에만 stall 시간이 적용된다. 커널 송신 버퍼가 비어 있는 동안은
쓰기 성공으로 보일 수 있으므로 zero-window 패킷 자체를 판별하는 기능은 아니다.
조금씩이라도 계속 진행되는 저속 연결은 이 제한만으로 차단되지 않는다.

half-close 제한은 한 방향 EOF를 관측한 뒤 나머지 방향을 정리할 때까지의
절대 시간이다. 정상 응답도 이 시간보다 길면 끊길 수 있어 0에서 시작할 수 있다.
`client_idle_ms`를 양수로 설정하면 클라이언트에서 게이트로 실제 데이터가
전혀 오지 않는 established relay만 종료한다. 서버가 보내는 데이터만으로는
idle 타이머가 연장되지 않는다. 따라서 양방향 keepalive를 정상적으로 주고받는
클라이언트와 함께 시험해야 하며, ViaFabric/프록시가 사용하는 keepalive 간격보다
충분히 크게 설정한다. 기본 0은 비활성이다.
두 기능과 backend_protection은 자원 보호이므로 `observe=true`에서도 활성화된다.
이를 관찰 전용 스위치로 착각하지 않는다. 연결 종료 외에 IP 차단은 하지 않는다.

## 자동 방어 유도 방지

컨트롤러의 기존 `adaptive` 안에 다음 키를 추가할 수 있다.

```json
"allow_emergency": false,
"required_signals": {"attack": ["pps", "active_prelogin"]}
```

이 예시는 `adaptive.thresholds.attack`에 두 신호의 enter/exit가 이미
실측 기준으로 설정되어 있어야 검증을 통과한다. 둘 다 enter 이상일 때만
attack으로 승격한다. 필요한 신호가 없으면 승격하지 않는다.
빈 `{}`는 기존 any-signal 동작이다. 정상 peak보다 낮은 threshold를 넣어서는 안 된다.
`conntrack_percent`도 보조 조건으로 사용할 수 있지만, 한 호스트의 다른 서비스
영향을 포함하므로 Minecraft 공격의 단독 증거로 쓰지 않는다.

## 적용과 검증

새 바이너리를 빌드/설치하고 JSON 검사를 통과한 뒤 정비 시간에 재시작한다.
게이트 재시작은 기존 접속을 끊는다. 이번 변경은 XDP 재부착을 요구하지 않는다.
`setup.sh`는 서비스를 중지한 상태에서 실행해야 하며 통합 테스트에 새 복구 시험이 포함된다.

```sh
sudo xddp-gate /etc/xddp/gate.json --check
sudo ddosctl --check
sudo systemctl restart xddp-controller
sudo systemctl restart xddp-gate
sudo ddosctl status
curl --noproxy '*' -sS http://127.0.0.1:9109/metrics
```

`relay_stall_timeouts`, `half_close_timeouts`, `backend_protection_rejected`,
`backend_circuit_opened`와 실제 로그인 성공률/게임 지연을 함께 본다.
과도한 종료가 발생하면 해당 선택 필드를 0으로 되돌리고 검증 후 재시작한다.
컨트롤러 관찰 모드로만 바꾸면 이러한 정적 자원 제한은 꺼지지 않는다.

## 이 계층에서 해결하지 않는 항목

- 수신 회선 포화와 대규모 ACK 폭주는 앞단 방어 역할이다.
- conntrack 점유율은 관측 기능이다. 게이트 제한이 연결 추적 테이블의 생성보다 늦게
  적용되므로 고갈을 완전히 예방하지 못한다.
- 암호화/압축 뒤 Minecraft 패킷, DB/명령어/청크/로그 작업은 실제 백엔드에서
  제한해야 한다. 압축을 풀거나 게임 패킷을 게이트에서 임의로 해석하지 않는다.
- Paper/Velocity/BotSentry의 인증 제한 시간, 작업별 제한, 오류 로그 집계,
  외부 조회의 캐시/동시량 상한을 별도로 확인한다. 해당 서버 소스/설정은 이 저장소에 없다.

## 이번 검증 범위

Windows의 격리된 Rust 1.85 GNU 도구로 컴파일, Rust 단위 테스트,
loopback TCP의 기존/PROXY v2·업로드·공정성·장애 복구 통합 시험을 수행한다.
Linux 전용 컨트롤러 I/O와 XDP 테스트는 Linux CI/실제 호스트에서 별도 실행해야 한다.
설치·CI 경로에 새 통합 시험을 포함했으며, CI 실행 결과는 별도 확인 대상이다.
