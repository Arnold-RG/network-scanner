# Packet Tracer Lab: VLANs, DHCP, Router-on-a-Stick and Hardening

A Cisco Packet Tracer lab in two parts. **Part 1** builds one router, two
switches, two VLANs, DHCP served by the router and inter-VLAN routing over a
single 802.1Q trunk ("router-on-a-stick"). **Part 2** hardens it: an extended
ACL that isolates the guest VLAN, SSH-only management on a dedicated VLAN,
login brute-force protection, port security and DHCP snooping.

> **Text-only lab.** This folder does **not** contain a `.pkt` file. You build
> the topology yourself in Packet Tracer and paste the configs below. That is
> deliberate: plain-text configs are easy to review, diff and reuse on real
> Cisco IOS gear.

## Topology

```
                 [ R1  Cisco 2911 ]
                        | Gi0/0
                        |  802.1Q trunk (VLAN 10,20)
                        | Gi0/1
                 [ SW1 2960-24TT ] Gi0/2 ---- trunk ---- Gi0/1 [ SW2 2960-24TT ]
                   Fa0/1     Fa0/2                          Fa0/1     Fa0/2
                     |         |                              |         |
                    PC1       PC2                            PC3       PC4
                  VLAN 10   VLAN 20                        VLAN 10   VLAN 20
```

Devices to drag in: 1 x 2911 router, 2 x 2960-24TT switches, 4 x PC.
Use **Copper Straight-Through** cables everywhere (Packet Tracer auto-MDIX
also accepts the switch-to-switch link).

| Link | From | To |
|------|------|----|
| Trunk | R1 Gi0/0 | SW1 Gi0/1 |
| Trunk | SW1 Gi0/2 | SW2 Gi0/1 |
| Access VLAN 10 | SW1 Fa0/1 | PC1 |
| Access VLAN 20 | SW1 Fa0/2 | PC2 |
| Access VLAN 10 | SW2 Fa0/1 | PC3 |
| Access VLAN 20 | SW2 Fa0/2 | PC4 |

## Addressing table

| Device | Interface | VLAN | IP address | Mask | Default gateway |
|--------|-----------|------|------------|------|-----------------|
| R1 | Gi0/0.10 | 10 (STAFF) | 192.168.10.1 | 255.255.255.0 | - |
| R1 | Gi0/0.20 | 20 (GUEST) | 192.168.20.1 | 255.255.255.0 | - |
| PC1 | NIC | 10 | DHCP (192.168.10.11+) | 255.255.255.0 | 192.168.10.1 |
| PC2 | NIC | 20 | DHCP (192.168.20.11+) | 255.255.255.0 | 192.168.20.1 |
| PC3 | NIC | 10 | DHCP (192.168.10.11+) | 255.255.255.0 | 192.168.10.1 |
| PC4 | NIC | 20 | DHCP (192.168.20.11+) | 255.255.255.0 | 192.168.20.1 |

Addresses .1 - .10 in each subnet are excluded from DHCP for static use.

## Router R1 configuration

```
enable
configure terminal
hostname R1
no ip domain-lookup
!
! The physical interface carries no IP; it just has to be up.
interface GigabitEthernet0/0
 description Trunk to SW1
 no ip address
 no shutdown
!
! One sub-interface per VLAN, each tagged with 802.1Q.
interface GigabitEthernet0/0.10
 description STAFF VLAN 10 gateway
 encapsulation dot1Q 10
 ip address 192.168.10.1 255.255.255.0
!
interface GigabitEthernet0/0.20
 description GUEST VLAN 20 gateway
 encapsulation dot1Q 20
 ip address 192.168.20.1 255.255.255.0
!
! DHCP: keep .1-.10 for static devices, hand out the rest.
ip dhcp excluded-address 192.168.10.1 192.168.10.10
ip dhcp excluded-address 192.168.20.1 192.168.20.10
!
ip dhcp pool STAFF
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
!
ip dhcp pool GUEST
 network 192.168.20.0 255.255.255.0
 default-router 192.168.20.1
!
end
write memory
```

## Switch SW1 configuration

```
enable
configure terminal
hostname SW1
no ip domain-lookup
!
vlan 10
 name STAFF
vlan 20
 name GUEST
!
! Uplink to the router
interface GigabitEthernet0/1
 description Trunk to R1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
! Link to SW2
interface GigabitEthernet0/2
 description Trunk to SW2
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
interface FastEthernet0/1
 description PC1 - STAFF
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
!
interface FastEthernet0/2
 description PC2 - GUEST
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
!
! Good practice: shut unused ports
interface range FastEthernet0/3 - 24
 shutdown
!
end
write memory
```

## Switch SW2 configuration

```
enable
configure terminal
hostname SW2
no ip domain-lookup
!
vlan 10
 name STAFF
vlan 20
 name GUEST
!
interface GigabitEthernet0/1
 description Trunk to SW1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
interface FastEthernet0/1
 description PC3 - STAFF
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
!
interface FastEthernet0/2
 description PC4 - GUEST
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
!
interface range FastEthernet0/3 - 24
 shutdown
!
end
write memory
```

## PCs

On each PC: **Desktop > IP Configuration > DHCP**. After a few seconds the PC
should show an address from its VLAN's pool. From **Desktop > Command Prompt**
you can also run `ipconfig /renew`.

## Verification

| Where | Command | What you should see |
|-------|---------|---------------------|
| R1 | `show ip interface brief` | Gi0/0, Gi0/0.10 and Gi0/0.20 `up/up` |
| R1 | `show ip route` | `C 192.168.10.0/24` and `C 192.168.20.0/24` connected routes |
| R1 | `show ip dhcp binding` | One lease per PC |
| SW1/SW2 | `show vlan brief` | VLAN 10 STAFF and VLAN 20 GUEST with the right access ports |
| SW1/SW2 | `show interfaces trunk` | Gi0/1 (and Gi0/2 on SW1) trunking, VLANs 10,20 allowed |
| PC1 | `ipconfig` | 192.168.10.x, gateway 192.168.10.1 |
| PC1 | `ping 192.168.10.1` | Replies from the gateway |
| PC1 | `ping <PC4 address>` | Replies - traffic is routed between VLANs by R1 |
| PC1 | `tracert <PC4 address>` | First hop 192.168.10.1, then PC4 |

The first ping in Packet Tracer often loses 1-2 packets while ARP resolves;
that is normal.

## Troubleshooting

- **PC gets 169.254.x.x** - DHCP is not reaching it: check the access VLAN on
  the switch port, that the VLAN is allowed on every trunk, and that the
  router sub-interface uses the matching `encapsulation dot1Q` number.
- **Can ping the gateway but not the other VLAN** - check the other PC got a
  gateway, and `show ip route` on R1 lists both subnets.
- **Sub-interfaces down** - the physical `Gi0/0` needs `no shutdown`.

## Part 2: Security hardening (ACL, SSH, management VLAN, port security)

Part 1 gives you a working network. Part 2 locks it down the way you would on
real Cisco IOS gear. Finish and verify Part 1 first.

### Goals

| Control | What it does |
|---------|--------------|
| Extended ACL `GUEST-IN` | GUEST (VLAN 20) can reach the internet side but not STAFF (VLAN 10), the management VLAN or the router's SSH/Telnet |
| Management VLAN 99 | Switches get an SVI in a separate VLAN; management traffic is kept away from user VLANs |
| SSH v2 only | Telnet is disabled, local user with a hashed `secret`, idle timeout, login brute-force protection |
| `access-class` on VTY | Only STAFF and MGMT subnets may even open an SSH session |
| Port security + DHCP snooping | Limit MACs per access port, drop rogue DHCP servers |

### Extra addressing

| Device | Interface | VLAN | IP address | Mask | Gateway |
|--------|-----------|------|------------|------|---------|
| R1 | Gi0/0.99 | 99 (MGMT) | 192.168.99.1 | 255.255.255.0 | - |
| SW1 | VLAN 99 SVI | 99 | 192.168.99.2 | 255.255.255.0 | 192.168.99.1 |
| SW2 | VLAN 99 SVI | 99 | 192.168.99.3 | 255.255.255.0 | 192.168.99.1 |

### R1: management sub-interface, SSH and ACLs

```
enable
configure terminal
!
! ---- base hardening ----
enable secret Use-A-Long-Passphrase-Here
service password-encryption
no ip http server
banner motd # Authorised access only. Activity is logged. #
!
! ---- management VLAN gateway ----
interface GigabitEthernet0/0.99
 description MGMT VLAN 99 gateway
 encapsulation dot1Q 99
 ip address 192.168.99.1 255.255.255.0
!
! ---- SSH v2 with a local user ----
ip domain-name lab.local
crypto key generate rsa general-keys modulus 2048
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
username admin privilege 15 secret Another-Long-Passphrase
! block logins for 120 s after 3 failures within 60 s
login block-for 120 attempts 3 within 60
!
! ---- who may open a VTY session ----
ip access-list standard MGMT-ONLY
 remark STAFF and MGMT subnets may manage the router
 permit 192.168.10.0 0.0.0.255
 permit 192.168.99.0 0.0.0.255
 deny   any log
!
line vty 0 4
 transport input ssh
 login local
 exec-timeout 10 0
 access-class MGMT-ONLY in
line console 0
 login local
 exec-timeout 10 0
!
! ---- GUEST isolation (applied inbound on the GUEST gateway) ----
ip access-list extended GUEST-IN
 remark DHCP from guests to the router must keep working
 permit udp any eq bootpc any eq bootps
 remark Guests may not reach STAFF or MGMT
 deny   ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255 log
 deny   ip 192.168.20.0 0.0.0.255 192.168.99.0 0.0.0.255 log
 remark Guests may not manage the router through its GUEST address
 deny   tcp 192.168.20.0 0.0.0.255 host 192.168.20.1 eq 22 log
 deny   tcp 192.168.20.0 0.0.0.255 host 192.168.20.1 eq telnet log
 remark Everything else (e.g. internet) is allowed
 permit ip 192.168.20.0 0.0.0.255 any
!
interface GigabitEthernet0/0.20
 ip access-group GUEST-IN in
end
write memory
```

> The passwords above are placeholders: choose your own. `crypto key generate`
> needs `hostname` and `ip domain-name` set first (Part 1 set the hostname).

### SW1 and SW2: management VLAN, SSH, port security, DHCP snooping

Run on **SW1** (use `192.168.99.3` and the SW2 port names on SW2):

```
enable
configure terminal
enable secret Use-A-Long-Passphrase-Here
service password-encryption
!
vlan 99
 name MGMT
!
! carry VLAN 99 on the trunks (on SW2 only Gi0/1 exists as a trunk)
interface range GigabitEthernet0/1 - 2
 switchport trunk allowed vlan 10,20,99
!
interface Vlan99
 ip address 192.168.99.2 255.255.255.0
 no shutdown
ip default-gateway 192.168.99.1
!
ip domain-name lab.local
crypto key generate rsa general-keys modulus 2048
ip ssh version 2
username admin privilege 15 secret Another-Long-Passphrase
line vty 0 15
 transport input ssh
 login local
 exec-timeout 10 0
!
! ---- port security: at most 2 MACs per access port, learned "sticky" ----
interface range FastEthernet0/1 - 2
 switchport port-security
 switchport port-security maximum 2
 switchport port-security mac-address sticky
 switchport port-security violation restrict
!
! ---- DHCP snooping: only the trunk towards R1 may send DHCP offers ----
ip dhcp snooping
ip dhcp snooping vlan 10,20
no ip dhcp snooping information option
interface GigabitEthernet0/1
 ip dhcp snooping trust
end
write memory
```

On **SW2**, trust its uplink `Gi0/1` instead: R1's DHCP offers reach SW2's
clients through it. SW1's `Gi0/2` (towards SW2) stays untrusted: client
requests are always allowed on untrusted ports; only server messages (offers,
acks) are dropped there, which is exactly what stops a rogue DHCP server.

R1 needs nothing extra for VLAN 99 on the trunk: on a router-on-a-stick, every
sub-interface's VLAN (here `Gi0/0.99`) is carried automatically.

### Verify the hardening

| Where | Command / action | Expected result |
|-------|------------------|-----------------|
| PC2 (GUEST) | `ping <PC1 address>` | `Destination host unreachable` from 192.168.20.1: the ACL blocks it |
| PC2 (GUEST) | `ping 192.168.20.1` | Replies: the gateway itself still answers |
| PC2 (GUEST) | `ssh -l admin 192.168.20.1` | Connection refused / timed out |
| PC1 (STAFF) | `ssh -l admin 192.168.10.1` | Password prompt, then `R1#` |
| PC1 (STAFF) | `telnet 192.168.10.1` | Refused: VTY lines accept SSH only |
| R1 | `show access-lists` | Match counters increase on the `deny` lines after the PC2 tests |
| R1 | `show ip ssh` | `SSH Enabled - version 2.0` |
| R1 | `show login` | Block-for settings and failure counts |
| SW1 | `show port-security interface fa0/1` | `Secure-up`, max MAC 2 |
| SW1 | `show ip dhcp snooping` | Snooping on VLANs 10,20 and the trusted uplink |
| PC1 (STAFF) | `ssh -l admin 192.168.99.2` | Reaches SW1 over the management VLAN |

### Connect it to the tools in this repo

On a real network built like this lab:

- `scan-network` from a STAFF PC finds STAFF hosts and the gateway, but a
  scan of `192.168.10.0/24` launched **from GUEST** finds nothing: that is the
  ACL working.
- `arp-spoof-detector --init` on a STAFF PC records R1's MAC. If someone on the
  segment poisons ARP, the gateway MAC changes and the detector raises a HIGH
  alert. DHCP snooping plus Dynamic ARP Inspection (`ip arp inspection vlan
  10,20` on real Catalyst switches; Packet Tracer support depends on the
  version) prevents the attack at the switch.
- The sibling project [port-scanner](https://github.com/Arnold-RG/port-scanner)
  run against R1 from STAFF should show only `22/tcp ssh`; Telnet (23) must
  be closed.

## Ideas to extend the lab

1. Move the native VLAN to an unused VLAN (e.g. 99) on every trunk
   (`switchport trunk native vlan 99`) and see what `show interfaces trunk` reports.
2. Add a syslog server (a Server-PT in VLAN 99) and send the ACL `log`
   matches to it with `logging host 192.168.99.10`.
3. Replace the static passwords with a AAA/TACACS+ server (Server-PT has an
   AAA service).
4. Add a second router and OSPF between them, then protect OSPF with MD5
   authentication.
