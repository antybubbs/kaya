# Cisco Secure Firewall / Firepower SNMPv3 validation checklist

This checklist is for a controlled read-only acceptance test. It does not
configure Cisco devices automatically and does not imply interoperability with
an untested FTD release.

## Before the test

- Record the exact FTD release and whether it is managed by FMC or configured
  directly through FDM. Use the matching Cisco configuration guide; menus and
  supported algorithms vary by release.
- Confirm Kaya can reach the selected FTD management address over UDP/161 and
  that intermediate ACLs permit only the Kaya host as an SNMP manager.
- Use an SNMPv3 read-only user with authentication and privacy. Prefer SHA or
  a SHA-2 option and AES128/AES192/AES256 where the device release exposes it.
  Do not use MD5 or DES for a new account on releases where Cisco has removed
  or deprecated them.
- For FMC-managed FTD, configure the SNMP policy, add Kaya as a polling host,
  save, and deploy the policy. Configuration is not active on the device until
  deployment completes.
- For FDM-managed FTD, configure SNMP on the device’s supported management
  interface and apply/save the device configuration. Confirm the exact
  release’s interface and user workflow first.

## Kaya validation

1. Open IP/WAN Monitor → Network Traffic → Sources.
2. Add the FTD management IP, UDP/161, SNMPv3 username, authentication and
   privacy algorithms, and credentials. Leave the source disabled while
   checking the configuration.
3. Run **Test connection**. Record only the safe result category, not
   credentials or raw protocol errors.
4. Run **Discover interfaces** and identify the routed WAN interface(s). Do not
   combine logical and physical interfaces unless the device design makes that
   relationship explicit.
5. Select monitored interfaces, designate WAN status, and map inbound/outbound
   directions. Save each interface independently.
6. Enable the source and then enable Network Traffic monitoring. Confirm the
   dashboard starts with a baseline and does not invent a rate before a second
   observation.
7. Compare Kaya’s interface names, advertised speed, `ifHCInOctets`,
   `ifHCOutOctets`, `sysUpTime` and observation times with an independent,
   read-only SNMP walk or Cisco-supported diagnostic. Compare rates only after
   matching the actual elapsed interval.
8. Leave the test running across a five-minute UTC boundary. Confirm the
   aggregate is split across buckets and marked estimated where interval
   distribution is approximate.
9. Disable the source during a polling interval. Confirm historical data
   remains visible and no new observations are written. Re-enable only if the
   acceptance owner approves.

## Troubleshooting

- **Authentication failure:** verify the username, authentication algorithm,
  authentication secret and the device’s configured SNMPv3 security level.
- **Timeout/device unavailable:** verify the FTD management IP, routed or
  diagnostic interface selection, UDP/161 ACLs, deployment/apply state and
  return routing.
- **Unsupported response:** verify the device exposes IF-MIB/IF-X-MIB and
  check whether high-capacity counters are available. Kaya can fall back to
  32-bit counters, but the result should be treated cautiously.
- **Unexpected totals:** verify interface selection and direction mapping,
  check for logical/physical duplication, and inspect discontinuity or device
  uptime changes before treating a delta as traffic.

Cisco’s versioned documentation should be consulted for the exact release:
[FMC/FTD configuration guides](https://www.cisco.com/c/en/us/support/security/firepower-ngfw/products-installation-and-configuration-guides-list.html),
[FMC SNMP guidance](https://docs.manage.security.cisco.com/cdfmc/t_configure-snmp-for-threat-defense.html),
and [FDM configuration guides](https://www.cisco.com/c/en/us/support/security/asa-5500-series-next-generation-firewalls/products-installation-and-configuration-guides-list.html).
