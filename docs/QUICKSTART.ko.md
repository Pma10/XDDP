# XDDP 간편 설치

지원 환경은 Debian 12/13 또는 Ubuntu 24.04의 systemd 호스트입니다. 설치 명령은 빌드 도구와 Rust 1.85를 준비하고, 전체 테스트를 실행한 뒤 파일을 설치합니다.

```sh
git clone https://github.com/Pma10/XDDP.git
cd XDDP
sudo sh scripts/setup.sh
```

설치 명령은 다음 작업을 자동으로 합니다.

- clang, libbpf, Python, 네트워크 도구와 Rust 빌드 환경 설치
- XDP와 Rust 게이트 빌드
- Rust, Python, 게이트 통합, PROXY v2 통합 테스트 실행
- `/sys/fs/bpf`를 필요할 때 마운트
- `/usr/local`의 실행 파일과 systemd 유닛 설치
- `/etc/xddp/controller.json`, `/etc/xddp/gate.json` 생성

기존 `/etc/xddp/*.json`은 덮어쓰지 않습니다. 서비스 시작, XDP 연결, 방화벽 변경, 공개 포트 변경도 하지 않습니다. 실행 중인 XDDP 서비스가 있으면 업그레이드를 거부하므로 먼저 정비 시간에 중지해야 합니다.

## 설치 후 설정

먼저 `/etc/xddp/gate.json`에서 게이트가 받을 주소와 기존 Velocity의 내부 백엔드 주소를 설정합니다. 실제 Velocity를 쓸 때는 신뢰된 내부 리스너에 PROXY v2를 설정하고 다음처럼 맞춥니다.

```json
"proxy_v2": true,
"allow_backend_identity_loss": false
```

`/etc/xddp/controller.json`에서는 `interface`, `pin_dir`, `owned_prefixes`, 보호할 TCP 포트를 실제 서버에 맞춥니다. 공인 주소나 필요한 라우팅 범위 전체를 무심코 `owned_prefixes`에 넣지 않습니다. 기본은 관찰 모드이며 모든 속도 제한은 0으로 비활성화되어 있습니다.

설정 검사는 다음으로 실행합니다.

```sh
sudo ddosctl --check
sudo xddp-gate /etc/xddp/gate.json --check
```

## 처음 시작하는 순서

서비스를 자동 활성화하지 않고, 관리 콘솔에서 순서대로 실행합니다.

```sh
sudo systemctl start xddp-controller
sudo ddosctl status
sudo ddosctl xdp status
```

실제 인터페이스에 붙이기 전에 staging에서 게이트를 실행하고 상태 조회, 로그인, 기존 플레이 중계를 확인합니다. 확인 후 게이트와 컨트롤러를 시작하고 현재 XDP 프로그램 ID가 없을 때만 다음 명령으로 연결합니다.

```sh
sudo systemctl start xddp-gate
sudo ddosctl xdp attach
```

`observe=true`를 유지한 채 지표를 관찰합니다. 제한값과 `status_connections`는 정상 접속·브라우저 상태 조회·BotSentry 검증량을 측정한 뒤 조정합니다. `observe off`는 별도 유지보수 판단으로 실행합니다.

샘플은 상태 조회를 로그인 핸드셰이크 예산과 분리하고
(`separate_status_budget=true`), 공격 모드에서도 짧은 정상 접속 burst를
보존합니다(`preserve_burst=true`). `status_ip`는 기본 0(비활성)이며 공유
NAT의 실제 상태 조회 동시량을 확인한 뒤에만 설정합니다. 속도와 burst 값은
실측값으로 정하고, 샘플의 0 값은 제한이 꺼진 상태입니다.

## XDP 대상 구분과 Gate 통계

XDP는 패킷의 목적지가 `owned_prefixes`에 있는지 확인한 뒤에만
비정상 IP 헤더의 차단을 적용합니다. 대상 주소를 확정할 수 없거나
비보호 대상인 트래픽은 통과시켜 Docker/Tailscale/기타 서비스를
잘못 차단할 위험을 줄였습니다. `ddosctl stats`는
`gate_counters` 필드에 Gate 누적 지표도 표시합니다.
`runtime_missing_reads`는 컨트롤러 런타임 파일이 없는 횟수이고,
`runtime_rejected_reads`는 존재하는 파일이 잘못됐거나 읽기 실패한 횟수입니다.
서비스 장애를 곧바로 DDoS 탐지로 해석하지 마십시오.

## 로그와 날짜별 공격 통계

```sh
sudo journalctl -u xddp-controller -n 80 --no-pager
sudo journalctl -u xddp-gate -n 80 --no-pager
sudo ddosctl stats
sudo ddosctl history 2026-10-06
sudo ddosctl history 2026-10-06 raw
```

새 컨트롤러는 분 단위 누적 통계를 `/var/lib/xddp/history.sqlite3`에 보존합니다.
기본 보관 기간은 30일이고, 기존 `/etc/xddp/controller.json`에 새 항목이 없어도
기본값을 사용합니다. SQLite는 IP별 차단 로그가 아니라 총계만 저장합니다.
설치 이전 날짜의 통계는 소급 생성할 수 없습니다. 날짜는 서버 로컬 시간입니다.

컨트롤러가 `Read-only file system: '/sys/fs/bpf/xddp'` 오류를 내면,
먼저 `findmnt -T /sys/fs/bpf`와 `systemctl cat xddp-controller`를 확인하십시오.
새 `xddp-bpffs.service`는 부팅 시 전용 디렉터리를 준비하며,
컨트롤러는 해당 디렉터리에만 쓰기 권한을 갖습니다. 반복 실패는
60초에 최대 다섯 번으로 제한됩니다. 기존 `override.conf`가 있으면
업그레이드 후에도 우선 적용되므로 반드시 검토하십시오.

운영 중인 `xddp-gate`를 멈추면 기존 접속자가 끊길 수 있습니다.
**로그 조회나 컨트롤러 단독 점검을 위해 Gate를 재시작하지 마십시오.**

## 업그레이드와 제거

송신 정체·반쪽 종료·백엔드 장애 반복 연결에 대한 선택적 보호 설정과
활성화 순서는 [추가 방어 설정](RESILIENCE.ko.md)을 참고하십시오.

소스 디렉터리에서 다시 `sudo sh scripts/setup.sh`를 실행하면 새 파일을 빌드하고 기존 설정을 보존합니다. 실행 중 서비스가 있으면 먼저 정비 시간에 다음을 실행합니다.

```sh
sudo systemctl stop xddp-gate xddp-controller
sudo sh scripts/setup.sh
```

긴급 분리는 다음을 사용합니다.

```sh
sudo xddp-rollback
```

이 명령은 설정된 세대와 현재 XDP 프로그램 ID가 일치할 때만 분리합니다. 게이트와 Java/Velocity 리스너 이동은 별도 작업입니다. 제거는 `sudo sh scripts/uninstall.sh`로 실행하며, 남은 핀과 설정은 복구를 위해 보존됩니다.
