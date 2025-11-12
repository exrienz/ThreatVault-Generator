#!/usr/bin/env python3
"""
Compliance Scan File Generator
Generates realistic Nessus compliance CSV files based on the ThreatVault format.

Usage: python compliance_gen.py <number_of_records> <output.csv>
"""

import csv
import random
import sys
from datetime import datetime, timedelta

# Compliance check templates - Name, Description, and Solution are linked
COMPLIANCE_CHECKS = [
    {
        "name": "Cisco IOS Compliance Checks",
        "severity_types": ["PASSED", "FAILED"],  # Automated checks only
        "checks": [
            {
                "id": "1.1.1",
                "title": "Enable 'aaa new-model'",
                "description": """This command enables the AAA access control system.

Authentication, authorization and accounting (AAA) services provide an authoritative source for managing and monitoring access for devices. Centralizing control improves consistency of access control, the services that may be accessed once authenticated and accountability by tracking services accessed. Additionally, centralizing access control simplifies and reduces administrative costs of account provisioning and de-provisioning, especially when managing a large number of devices.

Solution:
Globally enable authentication, authorization and accounting (AAA) using the new-model command.

hostname(config)#aaa new-model

Impact:

Implementing Cisco AAA is significantly disruptive as former access methods are immediately disabled. Therefore, before implementing Cisco AAA, the organization should carefully review and plan their authentication criteria (logins & passwords, challenges & responses, and token technologies), authorization methods, and accounting requirements.

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.1.1,800-171r3|03.01.01,800-53|AC-2(1),800-53r5|AC-2(1),CN-L3|7.1.3.2(d),CSCv7|16.2,CSCv8|5.6,CSF|PR.AC-1,CSF|PR.AC-4,CSF2.0|DE.CM-01,CSF2.0|DE.CM-03,CSF2.0|PR.AA-01,CSF2.0|PR.AA-05,CSF2.0|PR.DS-10,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(1),ISO-27001-2022|A.5.16,ISO-27001-2022|A.5.18,ISO-27001-2022|A.8.2,ISO/IEC-27001|A.9.2.1,ITSG-33|AC-2(1),LEVEL|1A,NIAv2|AM28,NIAv2|NS5j,NIAv2|SS14e,QCSC-v1|5.2.2,QCSC-v1|8.2.1,QCSC-v1|13.2,QCSC-v1|15.2

Policy Value:
CONFIG_CHECK
item: aaa new-model[ ]*$

Actual Value:
aaa new-model <----""",
                "solution": """Globally enable authentication, authorization and accounting (AAA) using the new-model command.

hostname(config)#aaa new-model

Impact:

Implementing Cisco AAA is significantly disruptive as former access methods are immediately disabled. Therefore, before implementing Cisco AAA, the organization should carefully review and plan their authentication criteria (logins & passwords, challenges & responses, and token technologies), authorization methods, and accounting requirements."""
            },
            {
                "id": "1.4.2",
                "title": "Enable 'service password-encryption'",
                "description": """When password encryption is enabled, the encrypted form of the passwords is displayed when a more system:running-config command is entered.

This requires passwords to be encrypted in the configuration file to prevent unauthorized users from learning the passwords just by reading the configuration. When not enabled, many of the device's passwords will be rendered in plain text in the configuration file. This service ensures passwords are rendered as encrypted strings preventing an attacker from easily determining the configured value.

Solution:
Enable password encryption service to protect sensitive access passwords in the device configuration.

hostname(config)#service password-encryption

Impact:

Organizations implementing 'service password-encryption' reduce the risk of unauthorized users learning clear text passwords to Cisco IOS configuration files. However, the algorithm used is not designed to withstand serious analysis and should be treated like clear-text.

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.5.2,800-171|3.13.16,800-171r3|03.05.07,800-171r3|03.13.08,800-53|IA-5(1),800-53|SC-28,800-53|SC-28(1),800-53r5|IA-5(1),800-53r5|SC-28,800-53r5|SC-28(1),CN-L3|8.1.4.7(b),CN-L3|8.1.4.8(b),CSCv7|16.4,CSCv8|3.11,CSF|PR.AC-1,CSF|PR.DS-1,CSF2.0|PR.AA-01,CSF2.0|PR.AA-03,CSF2.0|PR.DS-01,GDPR|32.1.a,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(2)(i),HIPAA|164.312(a)(2)(iv),HIPAA|164.312(d),HIPAA|164.312(e)(2)(ii),ISO-27001-2022|A.5.10,ISO-27001-2022|A.5.16,ISO-27001-2022|A.5.17,ISO-27001-2022|A.5.33,ITSG-33|IA-5(1),ITSG-33|SC-28,ITSG-33|SC-28a.,ITSG-33|SC-28(1),LEVEL|1A,NESA|T5.2.3,PCI-DSSv3.2.1|3.4,PCI-DSSv4.0|3.3.2,PCI-DSSv4.0|3.5.1,QCSC-v1|5.2.2,QCSC-v1|6.2,QCSC-v1|13.2,SWIFT-CSCv1|4.1,TBA-FIISB|28.1

Policy Value:
CONFIG_CHECK
item: service password-encryption

Actual Value:
service password-encryption <----""",
                "solution": """Enable password encryption service to protect sensitive access passwords in the device configuration.

hostname(config)#service password-encryption

Impact:

Organizations implementing 'service password-encryption' reduce the risk of unauthorized users learning clear text passwords to Cisco IOS configuration files. However, the algorithm used is not designed to withstand serious analysis and should be treated like clear-text."""
            },
            {
                "id": "1.5.1",
                "title": "Set 'no snmp-server' to disable SNMP when unused",
                "description": """If not in use, disable simple network management protocol (SNMP), read and write access.

SNMP read access allows remote monitoring and management of the device.

NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance.

Solution:
Disable SNMP read and write access if not in used to monitor and/or manage device.

hostname(config)#no snmp-server

Impact:

Organizations not using SNMP should require all SNMP services to be disabled by running the 'no snmp-server' command.

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.4.6,800-171|3.4.7,800-171r3|03.04.06b.,800-53|CM-7b.,800-53r5|CM-7b.,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CN-L3|8.1.4.4(b),CSCv7|9.2,CSF|PR.IP-1,CSF|PR.PT-3,CSF2.0|PR.PS-01,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|CM-7a.,LEVEL|1A,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,PCI-DSSv3.2.1|2.2.2,PCI-DSSv4.0|2.2.4,QCSC-v1|3.2,SWIFT-CSCv1|2.3

Policy Value:
CONFIG_CHECK_NOT
item: snmp-server community .+

Actual Value:
snmp-server community .+ not found in the configuration file""",
                "solution": """Disable SNMP read and write access if not in used to monitor and/or manage device.

hostname(config)#no snmp-server

Impact:

Organizations not using SNMP should require all SNMP services to be disabled by running the 'no snmp-server' command."""
            },
            {
                "id": "3.2.2",
                "title": "Set inbound 'ip access-group' on the External Interface",
                "description": """This command places the router in access-list configuration mode, where you must define the denied or permitted access conditions by using the deny and permit commands.

Configuring access controls can help prevent spoofing attacks. To reduce the effectiveness of IP spoofing, configure access control to deny any traffic from the external network that has a source address that should reside on the internal network. Include local host address or any reserved private addresses (RFC 1918).

Ensure the permit rule(s) above the final deny rule only allow traffic according to your organization's least privilege policy.

Solution:
Apply the access-group for the external (untrusted) interface

hostname(config)#interface {external_interface}
hostname(config-if)#ip access-group {name | number} in

Impact:

Organizations should plan and implement enterprise security policies explicitly permitting and denying access based upon access lists. Using the 'ip access-group' command enforces these policies by explicitly identifying groups permitted access.

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.1.16,800-171|3.1.17,800-171|3.4.1,800-171|3.4.2,800-171|3.4.6,800-171|3.4.7,800-171r3|03.01.16,800-171r3|03.04.01,800-171r3|03.04.02,800-171r3|03.04.06,800-53|AC-18,800-53|AC-18(1),800-53|AC-18(3),800-53|CM-2,800-53|CM-6,800-53|CM-7,800-53|CM-7(1),800-53|CM-9,800-53r5|AC-18,800-53r5|AC-18(1),800-53r5|AC-18(3),800-53r5|CM-2,800-53r5|CM-6,800-53r5|CM-7,800-53r5|CM-7(1),800-53r5|CM-9,CSCv7|9.2,CSCv8|4.2,CSF|DE.AE-1,CSF|PR.DS-7,CSF|PR.IP-1,CSF|PR.PT-3,CSF|PR.PT-4,CSF2.0|DE.CM-09,CSF2.0|ID.AM-08,CSF2.0|PR.AA-05,CSF2.0|PR.PS-01,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(1),ISO-27001-2022|A.5.2,ISO-27001-2022|A.5.14,ISO-27001-2022|A.8.9,ISO-27001-2022|A.8.20,ITSG-33|AC-18,ITSG-33|AC-18(1),ITSG-33|AC-18(3),ITSG-33|CM-2,ITSG-33|CM-6,ITSG-33|CM-7,ITSG-33|CM-7(1),ITSG-33|CM-9,LEVEL|1A,NESA|T1.2.1,NESA|T1.2.2,NESA|T3.2.5,NESA|T5.4.2,NESA|T7.5.1,NESA|T7.5.3,NESA|T7.6.1,NESA|T7.6.2,NESA|T7.6.3,NIAv2|NS33,NIAv2|NS34,NIAv2|NS38,NIAv2|SS15a,NIAv2|SS16,PCI-DSSv3.2.1|2.2.2,QCSC-v1|3.2,QCSC-v1|5.2.1,QCSC-v1|5.2.2,SWIFT-CSCv1|2.3

Policy Value:
CONFIG_CHECK
item: ip access-group CIS-BORDER-ACL in
context: interface GigabitEthernet2

Actual Value:
interface GigabitEthernet2/0/1
 description External interface
 switchport mode trunk

Expected configuration:
ip access-group CIS-BORDER-ACL in""",
                "solution": """Apply the access-group for the external (untrusted) interface

hostname(config)#interface {external_interface}
hostname(config-if)#ip access-group {name | number} in

Impact:

Organizations should plan and implement enterprise security policies explicitly permitting and denying access based upon access lists. Using the 'ip access-group' command enforces these policies by explicitly identifying groups permitted access."""
            },
            {
                "id": "1.2.3",
                "title": "Set 'exec-timeout' to less than or equal to 10 minutes",
                "description": """Setting an exec-timeout ensures that inactive sessions will be automatically logged out after a specified time period.

Without an automatic timeout, inactive sessions remain open indefinitely, increasing the window of opportunity for unauthorized access should a device be left unattended.

Solution:
Configure exec-timeout for all user-facing lines to 10 minutes or less.

hostname(config)#line console 0
hostname(config-line)#exec-timeout 10 0
hostname(config)#line vty 0 15
hostname(config-line)#exec-timeout 10 0

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.1.11,800-53|AC-11,800-53r5|AC-11,CSCv7|16.11,CSCv8|4.3,CSF|PR.AC-7,LEVEL|1A,PCI-DSSv4.0|8.2.8

Policy Value:
CONFIG_CHECK
item: exec-timeout [0-9] [0-5]?[0-9]|exec-timeout 10 0

Actual Value:
exec-timeout 15 0""",
                "solution": """Configure exec-timeout for all user-facing lines to 10 minutes or less.

hostname(config)#line console 0
hostname(config-line)#exec-timeout 10 0
hostname(config)#line vty 0 15
hostname(config-line)#exec-timeout 10 0"""
            },
            {
                "id": "1.3.1",
                "title": "Set 'no ip http server'",
                "description": """The HTTP server can be disabled if not needed for device management.

The HTTP protocol does not provide encryption and is susceptible to man-in-the-middle attacks. Organizations should disable the HTTP server if it is not required.

Solution:
Disable the HTTP server if not required for device management.

hostname(config)#no ip http server

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.4.6,800-171|3.4.7,800-53|CM-7,800-53r5|CM-7,CSCv7|9.2,CSCv8|4.8,CSF|PR.IP-1,CSF|PR.PT-3,LEVEL|1A,PCI-DSSv4.0|2.2.4

Policy Value:
CONFIG_CHECK_NOT
item: ip http server

Actual Value:
ip http server not found in configuration""",
                "solution": """Disable the HTTP server if not required for device management.

hostname(config)#no ip http server"""
            },
            {
                "id": "1.3.2",
                "title": "Set 'ip http secure-server'",
                "description": """HTTPS provides encrypted management communications over HTTP.

If HTTP access is required, HTTPS should be used instead of HTTP to protect credentials and configuration data in transit.

Solution:
Enable HTTPS server for encrypted web-based management.

hostname(config)#ip http secure-server

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.13.11,800-53|SC-8,800-53r5|SC-8,CSCv7|14.2,CSCv8|3.10,CSF|PR.DS-2,LEVEL|1A,PCI-DSSv4.0|4.2.1

Policy Value:
CONFIG_CHECK
item: ip http secure-server

Actual Value:
ip http secure-server <----""",
                "solution": """Enable HTTPS server for encrypted web-based management.

hostname(config)#ip http secure-server"""
            },
            {
                "id": "1.6.1",
                "title": "Set 'transport input ssh' for 'line vty' connections",
                "description": """Restrict VTY access to SSH only to ensure encrypted remote connections.

Telnet and other protocols transmit data in clear text, including authentication credentials. Restricting VTY lines to SSH ensures all remote administrative access is encrypted.

Solution:
Configure VTY lines to accept only SSH connections.

hostname(config)#line vty 0 15
hostname(config-line)#transport input ssh

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.1.13,800-171|3.13.11,800-53|AC-17(2),800-53|SC-8,800-53r5|AC-17(2),800-53r5|SC-8,CSCv7|4.5,CSCv8|3.10,CSF|PR.AC-3,CSF|PR.DS-2,LEVEL|1A,PCI-DSSv4.0|8.3.1

Policy Value:
CONFIG_CHECK
item: transport input ssh
context: line vty

Actual Value:
line vty 0 15
 transport input telnet ssh""",
                "solution": """Configure VTY lines to accept only SSH connections.

hostname(config)#line vty 0 15
hostname(config-line)#transport input ssh"""
            },
            {
                "id": "2.1.1",
                "title": "Set 'logging buffered' to appropriate size",
                "description": """Buffered logging stores log messages in router memory for local review.

Logging is essential for security monitoring, troubleshooting, and forensic analysis. Buffered logging should be configured with an appropriate buffer size to retain sufficient log data.

Solution:
Configure buffered logging with appropriate size (e.g., 64000 bytes).

hostname(config)#logging buffered 64000

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.3.1,800-171|3.3.2,800-53|AU-3,800-53|AU-12,800-53r5|AU-3,800-53r5|AU-12,CSCv7|6.2,CSCv8|8.2,CSF|DE.CM-1,CSF|DE.CM-7,LEVEL|1A,PCI-DSSv4.0|10.2.1

Policy Value:
CONFIG_CHECK
item: logging buffered [0-9]+

Actual Value:
logging buffered 64000 <----""",
                "solution": """Configure buffered logging with appropriate size (e.g., 64000 bytes).

hostname(config)#logging buffered 64000"""
            },
            {
                "id": "2.1.2",
                "title": "Set 'logging console critical'",
                "description": """Console logging should be limited to critical messages to avoid performance impact.

Excessive console logging can impact router performance and make the console difficult to use. Limiting console logging to critical messages ensures important alerts are visible without degrading performance.

Solution:
Configure console logging for critical messages only.

hostname(config)#logging console critical

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.3.1,800-53|AU-3,800-53r5|AU-3,CSCv7|6.2,CSCv8|8.2,LEVEL|1A

Policy Value:
CONFIG_CHECK
item: logging console critical

Actual Value:
logging console critical <----""",
                "solution": """Configure console logging for critical messages only.

hostname(config)#logging console critical"""
            },
            {
                "id": "2.2.1",
                "title": "Set 'logging trap informational'",
                "description": """Configure syslog to send informational and higher severity messages.

Centralized logging is critical for security monitoring and incident response. Configuring an appropriate logging level ensures important events are captured without generating excessive log volume.

Solution:
Configure syslog trap level to informational.

hostname(config)#logging trap informational

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.3.1,800-171|3.3.2,800-53|AU-3,800-53|AU-12,800-53r5|AU-3,800-53r5|AU-12,CSCv7|6.2,CSCv8|8.2,CSF|DE.CM-1,LEVEL|1A,PCI-DSSv4.0|10.2.1

Policy Value:
CONFIG_CHECK
item: logging trap informational

Actual Value:
logging trap warnings""",
                "solution": """Configure syslog trap level to informational.

hostname(config)#logging trap informational"""
            },
            {
                "id": "2.2.2",
                "title": "Set 'logging source-interface'",
                "description": """Configure a source interface for syslog messages to ensure consistent source IP addressing.

Using a source interface ensures syslog messages originate from a consistent IP address, simplifying log correlation and firewall rules.

Solution:
Configure a loopback interface as the source for syslog messages.

hostname(config)#logging source-interface Loopback0

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.3.8,800-53|AU-9,800-53r5|AU-9,CSCv7|6.6,CSCv8|8.9,LEVEL|1A

Policy Value:
CONFIG_CHECK
item: logging source-interface

Actual Value:
logging source-interface Loopback0 <----""",
                "solution": """Configure a loopback interface as the source for syslog messages.

hostname(config)#logging source-interface Loopback0"""
            },
            {
                "id": "2.3.1",
                "title": "Set 'service timestamps debug datetime'",
                "description": """Configure timestamps on debug messages with date and time information.

Accurate timestamps are essential for log analysis, troubleshooting, and security investigations. Debug messages should include both date and time.

Solution:
Enable timestamps on debug messages.

hostname(config)#service timestamps debug datetime msec localtime show-timezone

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.3.7,800-53|AU-8,800-53r5|AU-8,CSCv7|6.4,CSCv8|8.4,LEVEL|1A,PCI-DSSv4.0|10.6.1

Policy Value:
CONFIG_CHECK
item: service timestamps debug datetime

Actual Value:
service timestamps debug datetime msec localtime show-timezone <----""",
                "solution": """Enable timestamps on debug messages.

hostname(config)#service timestamps debug datetime msec localtime show-timezone"""
            },
            {
                "id": "2.3.2",
                "title": "Set 'service timestamps log datetime'",
                "description": """Configure timestamps on log messages with date and time information.

Accurate timestamps are essential for log analysis, troubleshooting, and security investigations. Log messages should include both date and time.

Solution:
Enable timestamps on log messages.

hostname(config)#service timestamps log datetime msec localtime show-timezone

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.3.7,800-53|AU-8,800-53r5|AU-8,CSCv7|6.4,CSCv8|8.4,LEVEL|1A,PCI-DSSv4.0|10.6.1

Policy Value:
CONFIG_CHECK
item: service timestamps log datetime

Actual Value:
service timestamps log datetime msec localtime show-timezone <----""",
                "solution": """Enable timestamps on log messages.

hostname(config)#service timestamps log datetime msec localtime show-timezone"""
            },
            {
                "id": "3.1.1",
                "title": "Set 'no ip source-route'",
                "description": """IP source routing allows the sender of a packet to specify the route the packet takes through the network.

Source routing can be exploited by attackers to bypass security controls. This feature should be disabled unless specifically required.

Solution:
Disable IP source routing.

hostname(config)#no ip source-route

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.1.20,800-53|AC-4,800-53r5|AC-4,CSCv7|9.2,CSCv8|13.5,CSF|PR.AC-5,LEVEL|1A,PCI-DSSv4.0|1.4.2

Policy Value:
CONFIG_CHECK_NOT
item: ip source-route

Actual Value:
ip source-route not found in configuration""",
                "solution": """Disable IP source routing.

hostname(config)#no ip source-route"""
            },
            {
                "id": "3.1.2",
                "title": "Set 'no ip proxy-arp'",
                "description": """Proxy ARP allows a router to respond to ARP requests on behalf of other devices.

Proxy ARP can be exploited for man-in-the-middle attacks and should be disabled on interfaces where it is not required.

Solution:
Disable proxy ARP on all interfaces where not required.

hostname(config)#interface GigabitEthernet0/1
hostname(config-if)#no ip proxy-arp

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.13.6,800-53|SC-7,800-53r5|SC-7,CSCv7|9.2,CSCv8|13.5,LEVEL|1A

Policy Value:
CONFIG_CHECK_NOT
item: ip proxy-arp
context: interface

Actual Value:
no ip proxy-arp found on all interfaces""",
                "solution": """Disable proxy ARP on all interfaces where not required.

hostname(config)#interface GigabitEthernet0/1
hostname(config-if)#no ip proxy-arp"""
            },
            {
                "id": "3.3.1",
                "title": "Set 'ip verify unicast source reachable-via'",
                "description": """Unicast Reverse Path Forwarding (uRPF) helps prevent IP address spoofing.

uRPF verifies that packets have a source address that is reachable via the interface on which the packet was received, helping to prevent spoofed packets.

Solution:
Enable uRPF on external interfaces.

hostname(config)#interface GigabitEthernet0/0
hostname(config-if)#ip verify unicast source reachable-via rx

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.1.18,800-53|AC-4(8),800-53r5|AC-4(8),CSCv7|9.2,CSCv8|13.5,LEVEL|2A

Policy Value:
CONFIG_CHECK
item: ip verify unicast source reachable-via
context: interface GigabitEthernet0/0

Actual Value:
interface GigabitEthernet0/0 does not have uRPF configured""",
                "solution": """Enable uRPF on external interfaces.

hostname(config)#interface GigabitEthernet0/0
hostname(config-if)#ip verify unicast source reachable-via rx"""
            },
            {
                "id": "4.1.1",
                "title": "Set 'login authentication' for 'line con 0'",
                "description": """Configure authentication for console access using AAA.

Console access should require authentication to prevent unauthorized physical access to the device from compromising security.

Solution:
Configure login authentication for console line.

hostname(config)#line con 0
hostname(config-line)#login authentication default

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.5.1,800-53|IA-2,800-53r5|IA-2,CSCv7|16.3,CSCv8|5.1,CSF|PR.AC-1,LEVEL|1A,PCI-DSSv4.0|8.3.1

Policy Value:
CONFIG_CHECK
item: login authentication
context: line con 0

Actual Value:
line con 0
 login authentication default <----""",
                "solution": """Configure login authentication for console line.

hostname(config)#line con 0
hostname(config-line)#login authentication default"""
            },
            {
                "id": "4.2.1",
                "title": "Set 'login authentication' for 'line vty'",
                "description": """Configure authentication for VTY access using AAA.

VTY access should require authentication to prevent unauthorized remote access to the device.

Solution:
Configure login authentication for VTY lines.

hostname(config)#line vty 0 15
hostname(config-line)#login authentication default

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.5.1,800-53|IA-2,800-53r5|IA-2,CSCv7|16.3,CSCv8|5.1,CSF|PR.AC-1,LEVEL|1A,PCI-DSSv4.0|8.3.1

Policy Value:
CONFIG_CHECK
item: login authentication
context: line vty

Actual Value:
line vty 0 15
 login authentication default <----""",
                "solution": """Configure login authentication for VTY lines.

hostname(config)#line vty 0 15
hostname(config-line)#login authentication default"""
            },
            {
                "id": "5.1.1",
                "title": "Set 'privilege 1' for local users",
                "description": """Local user accounts should be configured with the minimum necessary privilege level.

Assigning excessive privileges to user accounts increases the risk of unauthorized configuration changes. Users should be assigned privilege level 1 unless elevated privileges are specifically required.

Solution:
Configure local users with privilege level 1.

hostname(config)#username <user> privilege 1 secret <password>

See Also: https://workbench.cisecurity.org/benchmarks/17303

Reference: 800-171|3.1.5,800-53|AC-6,800-53r5|AC-6,CSCv7|4.3,CSCv8|6.1,CSF|PR.AC-4,LEVEL|1A,PCI-DSSv4.0|7.2.2

Policy Value:
CONFIG_CHECK
item: username .+ privilege 1

Actual Value:
username admin privilege 15 secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0""",
                "solution": """Configure local users with privilege level 1.

hostname(config)#username <user> privilege 1 secret <password>"""
            }
        ]
    },
    {
        "name": "Unix Compliance Checks",
        "severity_types": ["PASSED", "FAILED"],  # Automated checks only
        "checks": [
            {
                "id": "1.2.4",
                "title": "Ensure package manager repositories are configured",
                "description": """Systems need to have the respective package manager repositories configured to ensure that the system is able to receive the latest patches and updates.

If a system's package repositories are misconfigured, important patches may not be identified or a rogue repository could introduce compromised software.

NOTE: Nessus has provided the target output to assist in reviewing the benchmark to ensure target compliance.

Solution:
Configure your package manager repositories according to site policy.

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.11.2,800-171|3.11.3,800-171|3.14.1,800-171r3|03.11.02,800-171r3|03.14.01,800-53|RA-5,800-53|SI-2,800-53|SI-2(2),800-53r5|RA-5,800-53r5|RA-7,800-53r5|SI-2,800-53r5|SI-2(2),CN-L3|8.1.4.4(e),CN-L3|8.1.10.5(a),CN-L3|8.1.10.5(b),CN-L3|8.5.4.1(b),CN-L3|8.5.4.1(d),CN-L3|8.5.4.1(e),CSCv7|3.4,CSCv7|3.5,CSCv8|7.3,CSCv8|7.4,CSF|DE.CM-8,CSF|DE.DP-4,CSF|DE.DP-5,CSF|ID.RA-1,CSF|PR.IP-12,CSF|RS.CO-3,CSF|RS.MI-3,CSF2.0|GV.SC-10,CSF2.0|ID.IM-01,CSF2.0|ID.IM-02,CSF2.0|ID.IM-03,CSF2.0|ID.RA-01,CSF2.0|ID.RA-08,CSF2.0|PR.PS-02,GDPR|32.1.b,GDPR|32.1.d,HIPAA|164.306(a)(1),ISO-27001-2022|A.6.8,ISO-27001-2022|A.8.8,ISO-27001-2022|A.8.32,ISO/IEC-27001|A.12.6.1,ITSG-33|RA-5,ITSG-33|SI-2,ITSG-33|SI-2(2),LEVEL|1M,NESA|M1.2.2,NESA|M5.4.1,NESA|T7.6.2,NESA|T7.7.1,NIAv2|PR9,PCI-DSSv3.2.1|6.1,PCI-DSSv3.2.1|6.2,PCI-DSSv4.0|6.3,PCI-DSSv4.0|6.3.1,PCI-DSSv4.0|6.3.3,QCSC-v1|3.2,QCSC-v1|5.2.1,QCSC-v1|5.2.2,QCSC-v1|5.2.3,QCSC-v1|8.2.1,QCSC-v1|10.2.1,QCSC-v1|11.2,SWIFT-CSCv1|2.2,SWIFT-CSCv1|2.7

Policy Value:
cmd: /bin/dnf repolist
expect: ^Manual Review Required$

Actual Value:
The command '/bin/dnf repolist' returned :

Updating Subscription Management repositories.

repo id                            repo name
epel                               Extra Packages for Enterprise Linux 8 - x86_64
rhel-8-for-x86_64-appstream-rpms   Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms      Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)""",
                "solution": "Configure your package manager repositories according to site policy."
            },
            {
                "id": "5.2.1",
                "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
                "description": """The /etc/ssh/sshd_config file contains configuration specifications for sshd. The file should be protected from unauthorized modifications.

If unauthorized users gain access to /etc/ssh/sshd_config, they could modify SSH settings that may allow unauthorized access to the system.

Solution:
Run the following commands to set ownership and permissions on /etc/ssh/sshd_config:

# chown root:root /etc/ssh/sshd_config
# chmod og-rwx /etc/ssh/sshd_config

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.4.2,800-53|CM-6,800-53r5|CM-6,CSCv7|5.1,CSCv8|4.1,CSF|PR.IP-1,ITSG-33|CM-6,LEVEL|1S,PCI-DSSv3.2.1|2.2.4,PCI-DSSv4.0|2.2.6,SWIFT-CSCv1|2.3

Policy Value:
file: /etc/ssh/sshd_config
user: root
group: root
mode: [0-7]00

Actual Value:
/etc/ssh/sshd_config:
user: root
group: root
mode: 600""",
                "solution": """Run the following commands to set ownership and permissions on /etc/ssh/sshd_config:

# chown root:root /etc/ssh/sshd_config
# chmod og-rwx /etc/ssh/sshd_config"""
            },
            {
                "id": "5.3.4",
                "title": "Ensure SSH access is limited",
                "description": """There are several options available to limit which users and groups can access the system via SSH. It is recommended that at least one of the following options be leveraged: AllowUsers, AllowGroups, DenyUsers, DenyGroups.

Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.

Solution:
Edit the /etc/ssh/sshd_config file to set one or more of the parameters as follows:

AllowUsers <userlist>
AllowGroups <grouplist>
DenyUsers <userlist>
DenyGroups <grouplist>

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.5,800-53|AC-6(5),800-53r5|AC-6(5),CN-L3|8.1.10.6(a),CSCv7|16.7,CSCv8|3.3,CSF|PR.AC-4,ITSG-33|AC-6(5),LEVEL|1S,NESA|T5.1.1,NESA|T5.5.4,NIAv2|AM31,PCI-DSSv4.0|7.2.2

Policy Value:
file: /etc/ssh/sshd_config
expect: (AllowUsers|AllowGroups|DenyUsers|DenyGroups)

Actual Value:
/etc/ssh/sshd_config:
AllowUsers admin backup monitoring""",
                "solution": """Edit the /etc/ssh/sshd_config file to set one or more of the parameters as follows:

AllowUsers <userlist>
AllowGroups <grouplist>
DenyUsers <userlist>
DenyGroups <grouplist>"""
            },
            {
                "id": "1.8.2",
                "title": "Ensure GDM login banner is configured",
                "description": """GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.

Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place.

Solution:
Edit or create the file /etc/dconf/db/gdm.d/01-banner-message and add:

[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized users only. All activity may be monitored and reported.'

Run the following command to update the system databases:

# dconf update

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.9,800-53|AC-8,800-53r5|AC-8,CN-L3|8.1.4.1(a),CN-L3|8.1.4.1(b),CSCv7|5.1,CSF|PR.AC-7,ITSG-33|AC-8,LEVEL|1S,NESA|M5.2.5,NESA|T5.5.1,NIAv2|AM10a,NIAv2|AM10b,NIAv2|AM10c,NIAv2|AM10d,NIAv2|AM10e,PCI-DSSv4.0|2.2.6

Policy Value:
file: /etc/dconf/db/gdm.d/01-banner-message
regex: banner-message-enable=true

Actual Value:
/etc/dconf/db/gdm.d/01-banner-message not found""",
                "solution": """Edit or create the file /etc/dconf/db/gdm.d/01-banner-message and add:

[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized users only. All activity may be monitored and reported.'

Run the following command to update the system databases:

# dconf update"""
            },
            {
                "id": "1.1.1",
                "title": "Ensure mounting of cramfs filesystems is disabled",
                "description": """The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems.

Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.

Solution:
Edit or create a file in /etc/modprobe.d/ ending in .conf and add:

install cramfs /bin/true

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.4.6,800-171|3.4.7,800-53|CM-7,800-53r5|CM-7,CSCv7|9.2,CSCv8|4.8,LEVEL|1S

Policy Value:
cmd: /sbin/modprobe -n -v cramfs
expect: install /bin/true

Actual Value:
install cramfs /bin/true""",
                "solution": """Edit or create a file in /etc/modprobe.d/ ending in .conf and add:

install cramfs /bin/true"""
            },
            {
                "id": "1.5.1",
                "title": "Ensure core dumps are restricted",
                "description": """A core dump is the memory of an executable program. It is generally used to determine why a program aborted.

Setting a hard limit to 0 prevents users from overriding the soft limit. If core dumps are required, consider setting limits for user groups (see limits.conf(5)).

Solution:
Add the following line to /etc/security/limits.conf or a /etc/security/limits.d/* file:

* hard core 0

Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file:

fs.suid_dumpable = 0

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.7,800-53|AC-6(9),800-53r5|AC-6(9),CSCv7|5.1,CSCv8|3.3,LEVEL|1S

Policy Value:
file: /etc/security/limits.conf
regex: ^\s*\*\s+hard\s+core\s+0

Actual Value:
* hard core 0 found in /etc/security/limits.conf""",
                "solution": """Add the following line to /etc/security/limits.conf or a /etc/security/limits.d/* file:

* hard core 0

Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file:

fs.suid_dumpable = 0"""
            },
            {
                "id": "3.2.1",
                "title": "Ensure IP forwarding is disabled",
                "description": """The net.ipv4.ip_forward and net.ipv6.conf.all.forwarding flags are used to tell the system whether it can forward packets or not.

Setting the flags to 0 ensures that a system with multiple interfaces (e.g., a hard proxy), will never be able to forward packets, and therefore, never serve as a router.

Solution:
Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.20,800-53|AC-4,800-53r5|AC-4,CSCv7|9.2,CSCv8|4.8,LEVEL|1S

Policy Value:
sysctl: net.ipv4.ip_forward
expect: 0

Actual Value:
net.ipv4.ip_forward = 0""",
                "solution": """Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0"""
            },
            {
                "id": "3.2.2",
                "title": "Ensure packet redirect sending is disabled",
                "description": """ICMP Redirects are used to send routing information to other hosts.

An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system.

Solution:
Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.20,800-53|AC-4,800-53r5|AC-4,CSCv7|5.1,CSCv8|13.5,LEVEL|1S

Policy Value:
sysctl: net.ipv4.conf.all.send_redirects
expect: 0

Actual Value:
net.ipv4.conf.all.send_redirects = 1""",
                "solution": """Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0"""
            },
            {
                "id": "3.3.1",
                "title": "Ensure source routed packets are not accepted",
                "description": """In networking, source routing allows a sender to partially or fully specify the route packets take through a network.

Setting net.ipv4.conf.all.accept_source_route and net.ipv6.conf.all.accept_source_route to 0 disables the system from accepting source routed packets.

Solution:
Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.20,800-53|AC-4,800-53r5|AC-4,CSCv7|9.2,CSCv8|13.5,LEVEL|1S

Policy Value:
sysctl: net.ipv4.conf.all.accept_source_route
expect: 0

Actual Value:
net.ipv4.conf.all.accept_source_route = 0""",
                "solution": """Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0"""
            },
            {
                "id": "4.1.1",
                "title": "Ensure auditd is installed",
                "description": """auditd is the userspace component to the Linux Auditing System.

The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.

Solution:
Run the following command to install auditd:

# yum install audit audit-libs

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.3.1,800-171|3.3.2,800-53|AU-3,800-53|AU-12,800-53r5|AU-3,800-53r5|AU-12,CSCv7|6.2,CSCv8|8.2,LEVEL|2S

Policy Value:
rpm: audit
status: installed

Actual Value:
audit-2.8.5-4.el8.x86_64 installed""",
                "solution": """Run the following command to install auditd:

# yum install audit audit-libs"""
            },
            {
                "id": "4.2.1",
                "title": "Ensure rsyslog is installed",
                "description": """The rsyslog software is a recommended replacement to the original syslogd daemon.

The security enhancements of rsyslog such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server justify installing and configuring the package.

Solution:
Run the following command to install rsyslog:

# yum install rsyslog

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.3.1,800-53|AU-3,800-53r5|AU-3,CSCv7|6.2,CSCv8|8.2,LEVEL|1S

Policy Value:
rpm: rsyslog
status: installed

Actual Value:
rsyslog-8.2102.0-7.el8.x86_64 installed""",
                "solution": """Run the following command to install rsyslog:

# yum install rsyslog"""
            },
            {
                "id": "5.1.1",
                "title": "Ensure cron daemon is enabled",
                "description": """The cron daemon is used to execute batch jobs on the system.

While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and cron is used to execute them.

Solution:
Run the following command to enable cron:

# systemctl enable crond

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.4.2,800-53|CM-6,800-53r5|CM-6,CSCv7|5.1,LEVEL|1S

Policy Value:
systemd: crond
status: enabled

Actual Value:
crond.service enabled""",
                "solution": """Run the following command to enable cron:

# systemctl enable crond"""
            },
            {
                "id": "5.2.2",
                "title": "Ensure SSH Protocol is set to 2",
                "description": """Older versions of SSH support two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues.

SSH v2 is a more secure protocol that should be used instead of the legacy SSH v1 protocol.

Solution:
Edit the /etc/ssh/sshd_config file to set the parameter as follows:

Protocol 2

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.13,800-53|AC-17(2),800-53r5|AC-17(2),CSCv7|3.4,CSCv8|3.10,LEVEL|1S

Policy Value:
file: /etc/ssh/sshd_config
regex: ^\s*Protocol\s+2

Actual Value:
Protocol 2 found in /etc/ssh/sshd_config""",
                "solution": """Edit the /etc/ssh/sshd_config file to set the parameter as follows:

Protocol 2"""
            },
            {
                "id": "5.2.5",
                "title": "Ensure SSH LogLevel is appropriate",
                "description": """INFO level is the basic level that only records login activity of SSH users.

SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically not recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information.

Solution:
Edit the /etc/ssh/sshd_config file to set the parameter as follows:

LogLevel VERBOSE

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.3.1,800-171|3.3.2,800-53|AU-3,800-53|AU-12,800-53r5|AU-3,800-53r5|AU-12,CSCv7|6.2,CSCv8|8.2,LEVEL|1S

Policy Value:
file: /etc/ssh/sshd_config
regex: ^\s*LogLevel\s+(INFO|VERBOSE)

Actual Value:
LogLevel INFO""",
                "solution": """Edit the /etc/ssh/sshd_config file to set the parameter as follows:

LogLevel VERBOSE"""
            },
            {
                "id": "5.2.10",
                "title": "Ensure SSH root login is disabled",
                "description": """The PermitRootLogin parameter specifies if the root user can log in using ssh.

Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su. This in turn limits opportunity for non-repudiation.

Solution:
Edit the /etc/ssh/sshd_config file to set the parameter as follows:

PermitRootLogin no

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.1,800-171|3.1.5,800-53|AC-6,800-53r5|AC-6,CSCv7|4.3,CSCv8|5.4,LEVEL|1S,PCI-DSSv4.0|2.2.6

Policy Value:
file: /etc/ssh/sshd_config
regex: ^\s*PermitRootLogin\s+no

Actual Value:
PermitRootLogin yes""",
                "solution": """Edit the /etc/ssh/sshd_config file to set the parameter as follows:

PermitRootLogin no"""
            },
            {
                "id": "5.2.15",
                "title": "Ensure SSH warning banner is configured",
                "description": """The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted.

Banners are used to warn connecting users of the particular site's policy regarding connection.

Solution:
Edit the /etc/ssh/sshd_config file to set the parameter as follows:

Banner /etc/issue.net

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.9,800-53|AC-8,800-53r5|AC-8,CSCv7|5.1,LEVEL|1S

Policy Value:
file: /etc/ssh/sshd_config
regex: ^\s*Banner\s+/etc/issue.net

Actual Value:
Banner /etc/issue.net""",
                "solution": """Edit the /etc/ssh/sshd_config file to set the parameter as follows:

Banner /etc/issue.net"""
            },
            {
                "id": "5.4.1",
                "title": "Ensure password creation requirements are configured",
                "description": """The pam_pwquality.so module checks the strength of passwords.

Strong passwords protect systems from being hacked through brute force methods.

Solution:
Edit the /etc/security/pwquality.conf file to set password requirements:

minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.5.7,800-53|IA-5(1),800-53r5|IA-5(1),CSCv7|4.4,CSCv8|5.2,LEVEL|1S,PCI-DSSv4.0|8.3.6

Policy Value:
file: /etc/security/pwquality.conf
regex: ^\s*minlen\s*=\s*14

Actual Value:
minlen = 14 found in /etc/security/pwquality.conf""",
                "solution": """Edit the /etc/security/pwquality.conf file to set password requirements:

minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1"""
            },
            {
                "id": "5.4.2",
                "title": "Ensure lockout for failed password attempts is configured",
                "description": """Lock out users after n unsuccessful consecutive login attempts.

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced.

Solution:
Edit /etc/pam.d/password-auth and /etc/pam.d/system-auth to include:

auth required pam_faillock.so preauth silent deny=5 unlock_time=900

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.8,800-53|AC-7,800-53r5|AC-7,CSCv7|16.7,CSCv8|6.2,LEVEL|1S,PCI-DSSv4.0|8.3.4

Policy Value:
file: /etc/pam.d/system-auth
regex: pam_faillock.so.*deny=5

Actual Value:
auth required pam_faillock.so preauth silent deny=5 unlock_time=900""",
                "solution": """Edit /etc/pam.d/password-auth and /etc/pam.d/system-auth to include:

auth required pam_faillock.so preauth silent deny=5 unlock_time=900"""
            },
            {
                "id": "6.1.2",
                "title": "Ensure permissions on /etc/passwd are configured",
                "description": """The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.

It is critical to ensure that the /etc/passwd file is protected from unauthorized write access.

Solution:
Run the following command to set permissions on /etc/passwd:

# chmod 644 /etc/passwd

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.1.5,800-171|3.4.2,800-53|AC-6,800-53|CM-6,800-53r5|AC-6,800-53r5|CM-6,CSCv7|5.1,CSCv8|3.3,LEVEL|1S

Policy Value:
file: /etc/passwd
mode: 644

Actual Value:
/etc/passwd mode: 644""",
                "solution": """Run the following command to set permissions on /etc/passwd:

# chmod 644 /etc/passwd"""
            },
            {
                "id": "6.1.3",
                "title": "Ensure permissions on /etc/shadow are configured",
                "description": """The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.

If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it.

Solution:
Run the following command to set permissions on /etc/shadow:

# chmod 000 /etc/shadow

See Also: https://workbench.cisecurity.org/benchmarks/15286

Reference: 800-171|3.4.2,800-53|CM-6,800-53r5|CM-6,CSCv7|5.1,CSCv8|3.3,LEVEL|1S

Policy Value:
file: /etc/shadow
mode: 000

Actual Value:
/etc/shadow mode: 000""",
                "solution": """Run the following command to set permissions on /etc/shadow:

# chmod 000 /etc/shadow"""
            }
        ]
    },
    {
        "name": "Windows Compliance Checks",
        "severity_types": ["PASSED", "FAILED"],  # Automated checks only
        "checks": [
            {
                "id": "18.9.30.2",
                "title": "Ensure 'Configure solicited remote assistance' is set to 'Disabled'",
                "description": """Remote Assistance is a feature that allows a trusted helper to connect to a computer in order to provide assistance. Solicited Remote Assistance occurs when the user explicitly requests assistance via a ticket.

Configuring proper Remote Assistance settings helps prevent unauthorized access and reduces the attack surface. If solicited remote assistance is not properly controlled, it could allow unauthorized remote access to systems.

Solution:
To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\System\\Remote Assistance\\Configure Solicited Remote Assistance

Impact:

Users will not be able to request remote assistance from technical support staff.

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.4.6,800-171|3.4.7,800-53|CM-7,800-53r5|CM-7,CSCv7|9.2,CSCv8|4.8,CSF|PR.IP-1,CSF|PR.PT-3,ITSG-33|CM-7,LEVEL|1,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,PCI-DSSv4.0|2.2.4

Policy Value:
value_type: POLICY_DWORD
value_data: 0
reg_key: HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services
reg_item: fAllowToGetHelp

Actual Value:
[HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services] fAllowToGetHelp: 0""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\System\\Remote Assistance\\Configure Solicited Remote Assistance

Impact:

Users will not be able to request remote assistance from technical support staff."""
            },
            {
                "id": "2.3.10.5",
                "title": "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'",
                "description": """This policy setting determines what additional permissions are granted for anonymous connections to the computer.

If this policy setting is enabled, anonymous users can enumerate the names of domain accounts and network shares and perform certain other activities. This capability increases the attack surface of the system.

Solution:
To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Let Everyone permissions apply to anonymous users

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.5,800-53|AC-6,800-53r5|AC-6,CN-L3|8.1.10.6(a),CSCv7|9.2,CSF|PR.AC-4,CSF|PR.PT-3,ITSG-33|AC-6,LEVEL|1,NESA|T5.1.1,NIAv2|AM31,PCI-DSSv4.0|7.2.2

Policy Value:
value_type: POLICY_DWORD
value_data: 0
reg_key: HKLM\\System\\CurrentControlSet\\Control\\Lsa
reg_item: EveryoneIncludesAnonymous

Actual Value:
[HKLM\\System\\CurrentControlSet\\Control\\Lsa] EveryoneIncludesAnonymous: 0""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Let Everyone permissions apply to anonymous users"""
            },
            {
                "id": "18.9.84.2",
                "title": "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'",
                "description": """This policy setting controls whether users can enable online speech recognition services on their devices.

Online speech recognition services send voice data to Microsoft cloud services for processing. This may result in the transmission of sensitive information. Organizations should control whether users can utilize such services.

Solution:
To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\Control Panel\\Regional and Language Options\\Allow users to enable online speech recognition services

Impact:

Users will not be able to enable Cortana and other online speech recognition features.

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.3,800-53|AC-3,800-53r5|AC-3,CSCv8|3.3,CSF|PR.AC-4,CSF|PR.PT-3,ITSG-33|AC-3,LEVEL|2,NIAv2|AM3,PCI-DSSv4.0|7.2.2

Policy Value:
value_type: POLICY_DWORD
value_data: 0
reg_key: HKLM\\Software\\Policies\\Microsoft\\InputPersonalization
reg_item: AllowInputPersonalization

Actual Value:
[HKLM\\Software\\Policies\\Microsoft\\InputPersonalization] AllowInputPersonalization: 1

Expected value: 0""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\Control Panel\\Regional and Language Options\\Allow users to enable online speech recognition services

Impact:

Users will not be able to enable Cortana and other online speech recognition features."""
            },
            {
                "id": "1.1.1",
                "title": "Ensure 'Enforce password history' is set to '24 or more password(s)'",
                "description": """This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password.

The value for this policy setting must be between 0 and 24 passwords. Setting this policy to 0 does not enforce password history, which allows users to quickly reuse the same password.

Solution:
To establish the recommended configuration via GP, set the following UI path to 24 or more password(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Enforce password history

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.5.8,800-53|IA-5(1),800-53r5|IA-5(1),CSCv7|16,CSCv8|5.2,LEVEL|1,PCI-DSSv4.0|8.3.6

Policy Value:
value_type: POLICY_DWORD
value_data: 24

Actual Value:
PasswordHistorySize: 24""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to 24 or more password(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Enforce password history"""
            },
            {
                "id": "1.1.2",
                "title": "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
                "description": """This policy setting defines how long a user can use their password before it expires.

The value for this policy setting must be between 0 and 999 days. If you set it to 0, the password will never expire. Setting the maximum password age should reduce the risk of password compromise.

Solution:
To establish the recommended configuration via GP, set the following UI path to 365 or fewer days, but not 0:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Maximum password age

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.5.6,800-53|IA-5(1),800-53r5|IA-5(1),CSCv7|4.4,CSCv8|5.2,LEVEL|1,PCI-DSSv4.0|8.3.9

Policy Value:
value_type: POLICY_DWORD
value_data: 365

Actual Value:
MaximumPasswordAge: 90""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to 365 or fewer days, but not 0:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Maximum password age"""
            },
            {
                "id": "1.1.3",
                "title": "Ensure 'Minimum password age' is set to '1 or more day(s)'",
                "description": """This policy setting determines the number of days that you must use a password before you can change it.

The value for this policy setting must be between 0 and 999 days. Setting this policy to 0 allows immediate password changes, which could allow users to circumvent password history.

Solution:
To establish the recommended configuration via GP, set the following UI path to 1 or more day(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password age

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.5.8,800-53|IA-5(1),800-53r5|IA-5(1),CSCv7|4.4,CSCv8|5.2,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 1

Actual Value:
MinimumPasswordAge: 1""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to 1 or more day(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password age"""
            },
            {
                "id": "1.1.4",
                "title": "Ensure 'Minimum password length' is set to '14 or more character(s)'",
                "description": """This policy setting determines the least number of characters that make up a password for a user account.

There are many different theories about how to determine the best password length for an organization, but perhaps 'pass phrase' is a better term than 'password.' In Microsoft Windows 2000 or later, pass phrases can be quite long.

Solution:
To establish the recommended configuration via GP, set the following UI path to 14 or more character(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password length

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.5.7,800-53|IA-5(1),800-53r5|IA-5(1),CSCv7|4.4,CSCv8|5.2,LEVEL|1,PCI-DSSv4.0|8.3.6

Policy Value:
value_type: POLICY_DWORD
value_data: 14

Actual Value:
MinimumPasswordLength: 8""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to 14 or more character(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password length"""
            },
            {
                "id": "1.2.1",
                "title": "Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
                "description": """This policy setting determines the length of time that must pass before a locked account is unlocked and a user can try to log on again.

The value for this policy setting must be configured to 15 minutes or greater. A configuration value of 0 ensures that once locked out, accounts will remain locked out until an administrator manually unlocks them.

Solution:
To establish the recommended configuration via GP, set the following UI path to 15 or more minute(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Account lockout duration

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.8,800-53|AC-7,800-53r5|AC-7,CSCv7|16.7,CSCv8|6.2,LEVEL|1,PCI-DSSv4.0|8.3.4

Policy Value:
value_type: POLICY_DWORD
value_data: 15

Actual Value:
LockoutDuration: 15""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to 15 or more minute(s):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Account lockout duration"""
            },
            {
                "id": "1.2.2",
                "title": "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
                "description": """This policy setting determines the number of failed logon attempts before the account is locked.

Setting this policy to 0 does not conform with the benchmark as doing so disables the account lockout threshold. It is important to configure this threshold to prevent brute force attacks.

Solution:
To establish the recommended configuration via GP, set the following UI path to 5 or fewer invalid logon attempt(s), but not 0:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Account lockout threshold

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.8,800-53|AC-7,800-53r5|AC-7,CSCv7|16.7,CSCv8|6.2,LEVEL|1,PCI-DSSv4.0|8.3.4

Policy Value:
value_type: POLICY_DWORD
value_data: 5

Actual Value:
LockoutBadCount: 10""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to 5 or fewer invalid logon attempt(s), but not 0:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Account lockout threshold"""
            },
            {
                "id": "2.2.1",
                "title": "Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'",
                "description": """This policy setting allows other users on the network to connect to the computer.

This capability is required by a number of network protocols including SMB-based protocols, NetBIOS, CIFS, and COM+. Limiting access helps prevent unauthorized users from connecting to the system over the network.

Solution:
To establish the recommended configuration via GP, set the following UI path to Administrators, Remote Desktop Users:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment\\Access this computer from the network

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.5,800-53|AC-6,800-53r5|AC-6,CSCv7|5.1,CSCv8|5.4,LEVEL|1,PCI-DSSv4.0|7.2.2

Policy Value:
value_type: USER_RIGHTS
value_data: Administrators,Remote Desktop Users

Actual Value:
SeNetworkLogonRight: Administrators,Remote Desktop Users""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Administrators, Remote Desktop Users:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment\\Access this computer from the network"""
            },
            {
                "id": "2.2.10",
                "title": "Ensure 'Deny log on locally' to include 'Guests'",
                "description": """This security setting determines which users are prevented from logging on at the computer.

This policy setting supersedes the Allow log on locally policy setting if an account is subject to both policies. Denying local logon for Guest accounts helps prevent unauthorized access.

Solution:
To establish the recommended configuration via GP, set the following UI path to include Guests:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment\\Deny log on locally

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.5,800-53|AC-6,800-53r5|AC-6,CSCv7|16,CSCv8|5.4,LEVEL|1

Policy Value:
value_type: USER_RIGHTS
value_data: Guests

Actual Value:
SeDenyInteractiveLogonRight: Guests""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to include Guests:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment\\Deny log on locally"""
            },
            {
                "id": "2.3.1.1",
                "title": "Ensure 'Accounts: Administrator account status' is set to 'Disabled'",
                "description": """This policy setting enables or disables the Administrator account during normal operation.

The built-in Administrator account is the first account that is created during the installation. This account has full control over files, directories, services, and other resources on the local computer. It is recommended to disable this account.

Solution:
To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Accounts: Administrator account status

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.5,800-53|AC-6,800-53r5|AC-6,CSCv7|5.1,CSCv8|5.4,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 0
reg_key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
reg_item: EnableAdminAccount

Actual Value:
[HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System] EnableAdminAccount: 0""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Accounts: Administrator account status"""
            },
            {
                "id": "2.3.7.1",
                "title": "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'",
                "description": """This policy setting determines whether pressing CTRL+ALT+DEL is required before a user can log on.

Microsoft developed this feature to make it easier to identify when a Trojan horse program is attempting to intercept password information. Requiring CTRL+ALT+DEL before users log on ensures that users are communicating by means of a trusted path.

Solution:
To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Do not require CTRL+ALT+DEL

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.12,800-53|AC-11,800-53r5|AC-11,CSCv7|16.11,CSCv8|4.3,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 0
reg_key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
reg_item: DisableCAD

Actual Value:
[HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System] DisableCAD: 1""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Do not require CTRL+ALT+DEL"""
            },
            {
                "id": "2.3.7.5",
                "title": "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'",
                "description": """This policy setting determines the amount of inactivity time before the session is locked.

Setting a machine inactivity limit helps ensure that unattended computers are locked, requiring reauthentication before use.

Solution:
To establish the recommended configuration via GP, set the following UI path to 900 or fewer second(s), but not 0:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Machine inactivity limit

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.10,800-53|AC-11,800-53r5|AC-11,CSCv7|16.11,CSCv8|4.3,LEVEL|1,PCI-DSSv4.0|8.2.8

Policy Value:
value_type: POLICY_DWORD
value_data: 900
reg_key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
reg_item: InactivityTimeoutSecs

Actual Value:
[HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System] InactivityTimeoutSecs: 900""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to 900 or fewer second(s), but not 0:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Machine inactivity limit"""
            },
            {
                "id": "2.3.11.1",
                "title": "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'",
                "description": """This policy setting determines whether Local System services that use Negotiate will use the computer identity.

When services running as Local System connect to remote computers, they typically authenticate using the computer identity. Enabling this policy ensures proper authentication behavior.

Solution:
To establish the recommended configuration via GP, set the following UI path to Enabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Allow Local System to use computer identity for NTLM

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.5.2,800-53|IA-5,800-53r5|IA-5,CSCv7|16.13,CSCv8|5.9,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 1
reg_key: HKLM\\System\\CurrentControlSet\\Control\\Lsa
reg_item: UseMachineId

Actual Value:
[HKLM\\System\\CurrentControlSet\\Control\\Lsa] UseMachineId: 1""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Enabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Allow Local System to use computer identity for NTLM"""
            },
            {
                "id": "2.3.11.3",
                "title": "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'",
                "description": """This policy setting determines whether Windows stores a LAN Manager hash of the new password whenever the password is changed.

The LAN Manager hash is relatively weak compared to the Windows NT hash, so it is susceptible to attack. Ensuring this hash is not stored helps protect password security.

Solution:
To establish the recommended configuration via GP, set the following UI path to Enabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Do not store LAN Manager hash value on next password change

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.13.11,800-53|SC-13,800-53r5|SC-13,CSCv7|16.14,CSCv8|3.11,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 1
reg_key: HKLM\\System\\CurrentControlSet\\Control\\Lsa
reg_item: NoLMHash

Actual Value:
[HKLM\\System\\CurrentControlSet\\Control\\Lsa] NoLMHash: 1""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Enabled:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Do not store LAN Manager hash value on next password change"""
            },
            {
                "id": "2.3.11.6",
                "title": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
                "description": """This policy setting determines which challenge/response authentication protocol is used for network logons.

LAN Manager (LM) and NTLM authentications are less secure than NTLMv2. Organizations should configure systems to use only NTLMv2 for the strongest authentication.

Solution:
To establish the recommended configuration via GP, set the following UI path to Send NTLMv2 response only. Refuse LM & NTLM:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: LAN Manager authentication level

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.5.2,800-53|IA-5,800-53r5|IA-5,CSCv7|16.13,CSCv8|5.9,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 5
reg_key: HKLM\\System\\CurrentControlSet\\Control\\Lsa
reg_item: LmCompatibilityLevel

Actual Value:
[HKLM\\System\\CurrentControlSet\\Control\\Lsa] LmCompatibilityLevel: 3""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Send NTLMv2 response only. Refuse LM & NTLM:

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: LAN Manager authentication level"""
            },
            {
                "id": "9.1.1",
                "title": "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'",
                "description": """This setting determines whether Windows Firewall with Advanced Security is active or inactive for the Domain profile.

When computers are connected to networks where they can be authenticated by a domain controller, they should always have their firewall enabled to protect against network-based attacks.

Solution:
To establish the recommended configuration via GP, set the following UI path to On (recommended):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Windows Defender Firewall Properties\\Domain Profile\\Firewall state

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.3,800-171|3.13.6,800-53|AC-4,800-53|SC-7,800-53r5|AC-4,800-53r5|SC-7,CSCv7|9.4,CSCv8|13.1,LEVEL|1,PCI-DSSv4.0|1.2.1

Policy Value:
value_type: POLICY_DWORD
value_data: 1
reg_key: HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile
reg_item: EnableFirewall

Actual Value:
[HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile] EnableFirewall: 1""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to On (recommended):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Windows Defender Firewall Properties\\Domain Profile\\Firewall state"""
            },
            {
                "id": "9.2.1",
                "title": "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'",
                "description": """This setting determines whether Windows Firewall with Advanced Security is active or inactive for the Private profile.

When computers are connected to private networks such as home or small office networks, they should have their firewall enabled to protect against network-based attacks.

Solution:
To establish the recommended configuration via GP, set the following UI path to On (recommended):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Windows Defender Firewall Properties\\Private Profile\\Firewall state

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.3,800-171|3.13.6,800-53|AC-4,800-53|SC-7,800-53r5|AC-4,800-53r5|SC-7,CSCv7|9.4,CSCv8|13.1,LEVEL|1,PCI-DSSv4.0|1.2.1

Policy Value:
value_type: POLICY_DWORD
value_data: 1
reg_key: HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile
reg_item: EnableFirewall

Actual Value:
[HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile] EnableFirewall: 1""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to On (recommended):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Windows Defender Firewall Properties\\Private Profile\\Firewall state"""
            },
            {
                "id": "9.3.1",
                "title": "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'",
                "description": """This setting determines whether Windows Firewall with Advanced Security is active or inactive for the Public profile.

When computers are connected to public networks such as coffee shops or airports, they should have their firewall enabled to protect against network-based attacks from untrusted sources.

Solution:
To establish the recommended configuration via GP, set the following UI path to On (recommended):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Windows Defender Firewall Properties\\Public Profile\\Firewall state

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.1.3,800-171|3.13.6,800-53|AC-4,800-53|SC-7,800-53r5|AC-4,800-53r5|SC-7,CSCv7|9.4,CSCv8|13.1,LEVEL|1,PCI-DSSv4.0|1.2.1

Policy Value:
value_type: POLICY_DWORD
value_data: 1
reg_key: HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile
reg_item: EnableFirewall

Actual Value:
[HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile] EnableFirewall: 1""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to On (recommended):

Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Windows Defender Firewall Properties\\Public Profile\\Firewall state"""
            },
            {
                "id": "18.5.14.1",
                "title": "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'",
                "description": """This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver.

The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver: Good, Bad, Bad but required, or Unknown. Properly configuring this helps protect against malicious boot drivers.

Solution:
To establish the recommended configuration via GP, set the following UI path to Enabled: Good, unknown and bad but critical:

Computer Configuration\\Policies\\Administrative Templates\\System\\Early Launch Antimalware\\Boot-Start Driver Initialization Policy

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.14.2,800-53|SI-3,800-53r5|SI-3,CSCv7|8.3,CSCv8|10.1,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 3
reg_key: HKLM\\System\\CurrentControlSet\\Policies\\EarlyLaunch
reg_item: DriverLoadPolicy

Actual Value:
[HKLM\\System\\CurrentControlSet\\Policies\\EarlyLaunch] DriverLoadPolicy: 3""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Enabled: Good, unknown and bad but critical:

Computer Configuration\\Policies\\Administrative Templates\\System\\Early Launch Antimalware\\Boot-Start Driver Initialization Policy"""
            },
            {
                "id": "18.9.26.1.1",
                "title": "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'",
                "description": """This policy setting controls Event Log behavior when the log file reaches its maximum size.

If you disable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost. Organizations should ensure event logs do not overwrite important security events.

Solution:
To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Event Log Service\\Application\\Control Event Log behavior when the log file reaches its maximum size

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.3.1,800-53|AU-4,800-53r5|AU-4,CSCv7|6.4,CSCv8|8.3,LEVEL|1

Policy Value:
value_type: POLICY_DWORD
value_data: 0
reg_key: HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application
reg_item: Retention

Actual Value:
[HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application] Retention: 0""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Event Log Service\\Application\\Control Event Log behavior when the log file reaches its maximum size"""
            },
            {
                "id": "18.9.26.2.1",
                "title": "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'",
                "description": """This policy setting controls Security Event Log behavior when the log file reaches its maximum size.

Security event logs are critical for forensic analysis and compliance. Ensuring that these logs do not overwrite important events is crucial for maintaining an audit trail.

Solution:
To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Event Log Service\\Security\\Control Event Log behavior when the log file reaches its maximum size

See Also: https://workbench.cisecurity.org/benchmarks/16294

Reference: 800-171|3.3.1,800-53|AU-4,800-53r5|AU-4,CSCv7|6.4,CSCv8|8.3,LEVEL|1,PCI-DSSv4.0|10.5.1

Policy Value:
value_type: POLICY_DWORD
value_data: 0
reg_key: HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security
reg_item: Retention

Actual Value:
[HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security] Retention: 0""",
                "solution": """To establish the recommended configuration via GP, set the following UI path to Disabled:

Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Event Log Service\\Security\\Control Event Log behavior when the log file reaches its maximum size"""
            }
        ]
    },
    {
        "name": "Manual Security Review Checks",
        "severity_types": ["WARNING"],  # Manual review only
        "checks": [
            {
                "id": "MR-1.1",
                "title": "Review firewall rule complexity and necessity",
                "description": """Manual review is required to assess firewall rule complexity and necessity.

Firewall rules should be reviewed periodically to ensure they align with current security policies and business requirements. Complex or unnecessary rules can create security gaps or performance issues.

This check requires manual verification of:
- Rule count and complexity
- Rule ordering and priority
- Unused or redundant rules
- Rules that may conflict with security policy

Solution:
Review all firewall rules with your security team and:
1. Document the business justification for each rule
2. Remove unused or redundant rules
3. Simplify complex rule sets where possible
4. Ensure rules follow the principle of least privilege

See Also: https://www.cisecurity.org/insights/white-papers/cis-controls-v8

Reference: 800-171|3.13.6,800-53|SC-7,800-53r5|SC-7,CSCv8|13.1,CSF|PR.AC-5,CSF2.0|PR.AA-05,LEVEL|1

Policy Value:
MANUAL_REVIEW
Review firewall configuration for unnecessary complexity

Actual Value:
Manual verification required - automated testing not available""",
                "solution": """Review all firewall rules with your security team and:
1. Document the business justification for each rule
2. Remove unused or redundant rules
3. Simplify complex rule sets where possible
4. Ensure rules follow the principle of least privilege"""
            },
            {
                "id": "MR-1.2",
                "title": "Verify privileged account usage is appropriate",
                "description": """Manual review is required to verify that privileged accounts are being used appropriately.

Privileged accounts with administrative access should only be used when necessary and should be closely monitored. This check requires human judgment to assess whether privileged account usage patterns align with organizational policies.

This check requires manual verification of:
- Privileged account login patterns
- Tasks performed using privileged accounts
- Duration of privileged sessions
- Compliance with least privilege principles

Solution:
Review privileged account usage logs and:
1. Verify each privileged login has a legitimate business purpose
2. Ensure privileged accounts are not used for routine tasks
3. Confirm privileged sessions are terminated when no longer needed
4. Check that privileged account activity is properly logged and monitored

See Also: https://www.cisecurity.org/insights/white-papers/cis-controls-v8

Reference: 800-171|3.1.5,800-53|AC-6,800-53r5|AC-6,CSCv8|5.4,CSF|PR.AC-4,CSF2.0|PR.AA-01,LEVEL|1

Policy Value:
MANUAL_REVIEW
Verify privileged account usage patterns

Actual Value:
Manual verification required - requires analysis of account behavior""",
                "solution": """Review privileged account usage logs and:
1. Verify each privileged login has a legitimate business purpose
2. Ensure privileged accounts are not used for routine tasks
3. Confirm privileged sessions are terminated when no longer needed
4. Check that privileged account activity is properly logged and monitored"""
            },
            {
                "id": "MR-2.1",
                "title": "Review data classification and handling procedures",
                "description": """Manual review is required to verify data classification and handling procedures are properly implemented.

Organizations must classify their data based on sensitivity and apply appropriate security controls. This check requires manual assessment to verify that classification schemes are properly implemented and that data is handled according to its classification level.

This check requires manual verification of:
- Data classification policy implementation
- Proper labeling of sensitive data
- Access controls aligned with data classification
- Data handling procedures compliance

Solution:
Conduct a review of your data classification implementation:
1. Verify all sensitive data is properly classified
2. Ensure access controls match data sensitivity levels
3. Check that data handling procedures are documented and followed
4. Validate that staff are trained on data classification policies

See Also: https://www.cisecurity.org/insights/white-papers/cis-controls-v8

Reference: 800-171|3.1.3,800-53|AC-3,800-53r5|AC-3,CSCv8|3.1,CSF|PR.AC-4,CSF|PR.DS-5,CSF2.0|PR.AA-01,CSF2.0|PR.DS-01,LEVEL|1

Policy Value:
MANUAL_REVIEW
Verify data classification implementation

Actual Value:
Manual verification required - requires examination of data handling practices""",
                "solution": """Conduct a review of your data classification implementation:
1. Verify all sensitive data is properly classified
2. Ensure access controls match data sensitivity levels
3. Check that data handling procedures are documented and followed
4. Validate that staff are trained on data classification policies"""
            },
            {
                "id": "MR-3.1",
                "title": "Review incident response plan effectiveness",
                "description": """Manual review is required to assess the effectiveness of the incident response plan.

An effective incident response plan requires regular review and testing to ensure it remains current and effective. This check requires manual assessment of the plan's completeness, currency, and effectiveness based on recent incidents or exercises.

This check requires manual verification of:
- Incident response plan documentation
- Recent plan updates reflecting lessons learned
- Test/exercise results and findings
- Team member awareness and preparedness

Solution:
Review your incident response plan with your security team:
1. Verify the plan is up-to-date with current threat landscape
2. Ensure all team members are identified and trained
3. Review findings from recent incidents or tabletop exercises
4. Update the plan based on lessons learned
5. Schedule regular testing and updates

See Also: https://www.cisecurity.org/insights/white-papers/cis-controls-v8

Reference: 800-171|3.6.1,800-53|IR-4,800-53r5|IR-4,CSCv8|17.1,CSF|DE.DP-4,CSF|RS.CO-1,CSF2.0|RS.MA-01,LEVEL|1

Policy Value:
MANUAL_REVIEW
Review incident response plan currency and effectiveness

Actual Value:
Manual verification required - requires assessment of plan quality and readiness""",
                "solution": """Review your incident response plan with your security team:
1. Verify the plan is up-to-date with current threat landscape
2. Ensure all team members are identified and trained
3. Review findings from recent incidents or tabletop exercises
4. Update the plan based on lessons learned
5. Schedule regular testing and updates"""
            },
            {
                "id": "MR-4.1",
                "title": "Assess third-party vendor security practices",
                "description": """Manual review is required to assess the security practices of third-party vendors.

Third-party vendors with access to organizational systems or data present security risks that must be managed. This check requires manual assessment of vendor security practices, contracts, and compliance with security requirements.

This check requires manual verification of:
- Vendor security assessment documentation
- Contract security requirements
- Vendor compliance with security standards
- Regular security reviews and audits

Solution:
Conduct a review of third-party vendor security practices:
1. Review all vendors with system/data access
2. Verify security requirements are included in contracts
3. Collect and review vendor security assessments
4. Ensure vendors comply with relevant security standards
5. Schedule regular security reviews for high-risk vendors

See Also: https://www.cisecurity.org/insights/white-papers/cis-controls-v8

Reference: 800-171|3.12.3,800-53|SA-9,800-53r5|SA-9,CSCv8|15.1,CSF|ID.SC-1,CSF|ID.SC-2,CSF2.0|ID.AM-08,LEVEL|1

Policy Value:
MANUAL_REVIEW
Verify third-party vendor security practices

Actual Value:
Manual verification required - requires examination of vendor relationships and security controls""",
                "solution": """Conduct a review of third-party vendor security practices:
1. Review all vendors with system/data access
2. Verify security requirements are included in contracts
3. Collect and review vendor security assessments
4. Ensure vendors comply with relevant security standards
5. Schedule regular security reviews for high-risk vendors"""
            }
        ]
    }
]

# Scan information template
SCAN_INFO_DESCRIPTION = """This plugin displays, for each tested host, information about the
scan itself :

  - The version of the plugin set.
  - The type of scanner (Nessus or Nessus Home).
  - The version of the Nessus Engine.
  - The port scanner(s) used.
  - The port range scanned.
  - The ping round trip time
  - Whether credentialed or third-party patch management
    checks are possible.
  - Whether the display of superseded patches is enabled
  - The date of the scan.
  - The duration of the scan.
  - The number of hosts scanned in parallel.
  - The number of checks done in parallel."""


def generate_scan_info(scan_date):
    """Generate scan information plugin output"""
    duration = random.randint(30, 300)
    plugin_version = f"2025{random.randint(1, 12):02d}{random.randint(1, 28):02d}{random.randint(1000, 2359):04d}"

    return f"""Information about this scan :

Nessus version : 10.8.{random.randint(1, 5)}
Nessus build : {random.randint(20000, 20100)}
Plugin feed version : {plugin_version}
Scanner edition used : Nessus
Scanner OS : LINUX
Scanner distribution : es8-x86-64
Scan type : Normal
Scan name : compliance-scan-{random.randint(1000, 9999)}
Scan policy used : Offline Config Audit
Scanner IP : 127.0.0.1
Ping RTT : Unavailable
Thorough tests : no
Experimental tests : no
Scan for Unpatched Vulnerabilities : no
Plugin debugging enabled : no
Paranoia level : 1
Report verbosity : 1
Safe checks : yes
Optimize the test : yes
Credentialed checks : yes (on the localhost)
Attempt Least Privilege : no
Patch management checks : None
Display superseded patches : yes (supersedence plugin did not launch)
CGI scanning : disabled
Web application tests : disabled
Max hosts : {random.randint(50, 100)}
Max checks : {random.randint(3, 5)}
Recv timeout : 5
Backports : None
Allow post-scan editing : Yes
Nessus Plugin Signature Checking : Enabled
Audit File Signature Checking : Disabled
Scan Start Date : {scan_date.strftime('%Y/%m/%d %H:%M')} +08 (UTC +08:00)
Scan duration : {duration} sec
Scan for malware : no
"""


def generate_compliance_record(host_ip, check_type, check_data, risk_status):
    """Generate a single compliance check record"""
    check_id = check_data["id"]
    check_title = check_data["title"]
    full_name = f'"{check_id} {check_title}"'

    # Build description with proper formatting
    description = f'"{full_name}" : [{risk_status}]\n\n'
    description += check_data["description"]

    # Add manual review notice for warnings
    plugin_output = ""
    if risk_status == "WARNING":
        plugin_output = f"""*** MANUAL REVIEW REQUIRED ***
Check ID: {check_id}
Check Name: {check_title}
Host: {host_ip}
Check Type: {check_type}

This check returned a WARNING status and requires manual verification to determine compliance.
Please review the configuration details in the Description field and verify against your organization's security policy."""

    return {
        "CVE": "",
        "Risk": risk_status,
        "Host": host_ip,
        "Port": "0",
        "Name": check_type,
        "Description": description,
        "Solution": check_data["solution"],
        "Plugin Output": plugin_output,
        "VPR Score": ""
    }


def generate_compliance_csv(num_records, output_file):
    """Generate compliance CSV file with realistic data"""

    if num_records < 1:
        print("Error: Number of records must be at least 1")
        sys.exit(1)

    # Generate scan date (random date in the last 30 days)
    scan_date = datetime.now() - timedelta(days=random.randint(0, 30))

    records = []

    # First record: Nessus Scan Information (always at 127.0.0.1)
    records.append({
        "CVE": "",
        "Risk": "None",
        "Host": "127.0.0.1",
        "Port": "0",
        "Name": "Nessus Scan Information",
        "Description": SCAN_INFO_DESCRIPTION,
        "Solution": "n/a",
        "Plugin Output": generate_scan_info(scan_date),
        "VPR Score": ""
    })

    # Track which hosts have been assigned which check types
    host_check_mapping = {}

    # Generate compliance check records
    for i in range(1, num_records):
        # Generate IP address in range 192.168.1.1-192.168.1.255
        last_octet = ((i - 1) % 254) + 1
        host_ip = f"192.168.1.{last_octet}"

        # If host already has a check type, use that. Otherwise, assign a new one
        if host_ip not in host_check_mapping:
            # Select a random compliance check type
            check_category = random.choice(COMPLIANCE_CHECKS)
            host_check_mapping[host_ip] = check_category
        else:
            check_category = host_check_mapping[host_ip]

        # Select a random check from this category
        check_data = random.choice(check_category["checks"])

        # Assign severity based on allowed types for this category
        allowed_severities = check_category.get("severity_types", ["PASSED", "FAILED", "WARNING"])

        if len(allowed_severities) == 1:
            # Only one severity allowed (e.g., WARNING-only checks)
            risk_status = allowed_severities[0]
        elif "WARNING" in allowed_severities and len(allowed_severities) == 1:
            # WARNING-only category
            risk_status = "WARNING"
        elif "WARNING" not in allowed_severities:
            # PASSED/FAILED only (no WARNING)
            risk_status = random.choices(
                ["PASSED", "FAILED"],
                weights=[70, 30],  # 70% pass, 30% fail
                k=1
            )[0]
        else:
            # Mixed severities allowed (backward compatibility)
            risk_status = random.choices(
                ["PASSED", "FAILED", "WARNING"],
                weights=[70, 20, 10],  # 70% pass, 20% fail, 10% warning
                k=1
            )[0]

        record = generate_compliance_record(
            host_ip,
            check_category["name"],
            check_data,
            risk_status
        )

        records.append(record)

    # Write to CSV file
    fieldnames = ["CVE", "Risk", "Host", "Port", "Name", "Description", "Solution", "Plugin Output", "VPR Score"]

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)

        print(f"Successfully generated {len(records)} compliance records in '{output_file}'")
        print(f"\nStatistics:")
        print(f"  - Unique hosts: {len(host_check_mapping)}")

        # Count by risk status
        risk_counts = {"PASSED": 0, "FAILED": 0, "WARNING": 0, "None": 0}
        for record in records:
            risk_counts[record["Risk"]] += 1

        print(f"  - PASSED: {risk_counts['PASSED']}")
        print(f"  - FAILED: {risk_counts['FAILED']}")
        print(f"  - WARNING: {risk_counts['WARNING']}")
        print(f"  - Info (Scan Information): {risk_counts['None']}")

    except Exception as e:
        print(f"Error writing to file: {e}")
        sys.exit(1)


def main():
    if len(sys.argv) != 3:
        print("Usage: python compliance_gen.py <number_of_records> <output.csv>")
        print("\nExample: python compliance_gen.py 100 output.csv")
        print("\nNote: Number of records includes 1 scan information record + compliance checks")
        sys.exit(1)

    try:
        num_records = int(sys.argv[1])
    except ValueError:
        print("Error: First argument must be an integer (number of records)")
        sys.exit(1)

    output_file = sys.argv[2]

    if not output_file.endswith('.csv'):
        print("Warning: Output file should have .csv extension")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)

    generate_compliance_csv(num_records, output_file)


if __name__ == "__main__":
    main()
