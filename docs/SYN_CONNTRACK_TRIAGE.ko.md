# SYN Flood 및 Conntrack 포화 대응 절차

이 문서는 XDDP의 설계·코드에 근거한 **진단 및 단계적 적용 가이드**다.
XDDP가 실제 DDoS를 막았거나, 특정 PPS에서 정상 플레이어 지연이 없다는 검증 결과가 아니다.

## 1. 공격 시각과 증거를 분리해서 확인

운영체제 시간대를 먼저 확인한다.

```sh
timedatectl
```

sysstat가 설치돼 과거 `saDD` 데이터를 기록했을 때만 다음 명령을 실행한다.
`sar`의 시간은 샘플 **종료 시각**이므로 19:50의 수치는 대체로 19:40~19:50
구간 평균이다. 초당 최대 PPS 또는 순간 최고 Mbps와 혼동하지 않는다.

```sh
sar -n DEV --iface=eth0 -f /var/log/sysstat/sa05 -s 19:30:00 -e 20:10:00
sar -n EDEV --iface=eth0 -f /var/log/sysstat/sa05 -s 19:30:00 -e 20:10:00
sar -n SOCK -f /var/log/sysstat/sa05 -s 19:30:00 -e 20:10:00
sar -P ALL -u ALL -f /var/log/sysstat/sa05 -s 19:30:00 -e 20:10:00
sar -q -f /var/log/sysstat/sa05 -s 19:30:00 -e 20:10:00
```

```sh
journalctl -k --since "2026-10-05 19:30:00" --until "2026-10-05 20:10:00" --no-pager |
  grep -Ei 'Possible SYN flooding|nf_conntrack: table full|net_ratelimit'
```

- `Possible SYN flooding`은 SYN backlog 압박 징후이며 단독으로 공격의 출발지나 양을 증명하지 않는다.
- `nf_conntrack: table full, dropping packet`은 연결 추적 고갈에 따른 **커널 단계의 실제 패킷 손실**이다.
- `rxdrop/s=0`이어도 Conntrack이 패킷을 버릴 수 있다. 두 계층의 카운터가 다르다.
- `net_ratelimit: ... callbacks suppressed`는 누락된 **로그 메시지** 수이지 드롭된 패킷 수가 아니다.
- `tcpsck`와 `nf_conntrack_count`는 서로 다른 지표다. 현재 sysctl 값으로 과거 테이블 크기를 역산할 수 없다.
- `sar -n TCP,ETCP` 또는 `sar -I SUM`에 활동이 없으면 당시 수집하지 않은 기록이며 소급 복원되지 않는다.

## 2. XDDP가 실제로 차단하고 있는지 검증

먼저 **읽기 전용**으로 점검한다.

```sh
systemctl is-active xddp-controller xddp-gate
ip -details link show dev eth0
sudo ddosctl status
sudo ddosctl stats
sudo ddosctl xdp status
sudo ddosctl config show
```

확인할 항목:

1. XDP 프로그램이 올바른 인터페이스에 실제 부착돼 있는가? 해당 NIC가 드라이버 모드를 지원하는가?
2. `owned_prefixes`에 **실제 XDP가 관측하는 목적지 IP/CIDR**이 들어 있는가?
3. `protected_tcp_ports`에 서비스 포트가 포함되는가? DNAT/상위 프록시 경로는 확인했는가?
4. `observe`가 `false`인가? `manual_mode`/자동 모드와 별도로 확인한다.
5. 현재 모드의 `syn_per_cpu.rate`·`burst`가 **0이 아닌 측정된 값**인가? 0이면 XDP SYN 제한은 비활성이다.
6. `candidate_reasons.syn_rate`가 증가하는가? 실제 `drop_packets`도 증가하는가? 이 값만으로 정상 유저 보호를 확정하지 않는다.

Rust 게이트의 글로벌/IP/프리픽스 접속 예산은 **TCP accept 이후** 동작하므로
SYN backlog나 커널 Conntrack 테이블을 단독으로 보호할 수 없다. XDP SYN
예산도 CPU별이며 전체 NIC 트래픽에 대한 정확한 합산 제한이 아니다.
정상 ACK/RST/PSH처럼 보이는 패킷이나 회선 포화는 업스트림 보호가 필요하다.
XDP가 NIC에 도달한 패킷을 버려도 이미 소모한 상위 회선 대역폭은 복구할 수 없다.

## 3. 차단 활성화 전 검증

1. 운영 중인 XDP 프로그램, 방화벽, Docker/Tailscale, IPv4/IPv6, 라우팅 및 공개 리스너를 목록화한다.
2. 정상 동시 접속, 공유 NAT의 집단 재접속, 서버 목록 상태 조회, 고지연 PvP를 계측한다.
3. 별도 staging에서 `observe=true`로 정책 후보·오탐을 관측한다.
4. SYN 예산과 게이트 전역/출발지 예산을 **실측 정상 burst보다 안전하게 높게** 잡고, 별도 정비 시간에만 관측 모드 해제를 검토한다.
5. XDP 적용 전후의 정상 로그인 성공률, 유지 중이던 PvP 연결 끊김, p95/p99 지연·지터, MSPT, CPU별 softirq, Conntrack 드롭을 비교한다.
6. 예기치 않은 손실에 대비해 콘솔 접근·XDP 분리·게이트와 백엔드 리스너 복구 절차를 먼저 시험한다.

`ddosctl mode attack`만으로 `observe`가 해제되지 않는다. 기본 샘플 설정은
`observe=true`, 모든 SYN 속도 제한 0, `owned_prefixes=[]`이다.
자동 모드 임계값 역시 기본값에는 없다. 따라서 기본 설정에서 방어 성공을 기대하면 안 된다.

공격이 회선 또는 호스트 전체를 포화시킨다면 XDDP만으로 해결할 수 없으며,
상위 DDoS 정화 서비스에서 차단해야 한다.
