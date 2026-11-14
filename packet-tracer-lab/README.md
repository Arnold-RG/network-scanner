# Packet Tracer Lab: Two VLANs, DHCP and Router-on-a-Stick

A beginner-friendly Cisco Packet Tracer lab: one router, two switches, two
VLANs, DHCP served by the router, and inter-VLAN routing over a single 802.1Q
trunk ("router-on-a-stick").

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

## Ideas to extend the lab

1. Move the native VLAN to an unused VLAN (e.g. 99) on every trunk
   (`switchport trunk native vlan 99`) and see what `show interfaces trunk` reports.
2. Add an extended ACL on R1 so GUEST (VLAN 20) cannot reach STAFF (VLAN 10)
   but can still reach the gateway.
3. Add a management VLAN with an SVI on each switch and SSH access.
4. Enable port security on the access ports (`switchport port-security`).
