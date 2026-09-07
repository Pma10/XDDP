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

## 업그레이드와 제거

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
