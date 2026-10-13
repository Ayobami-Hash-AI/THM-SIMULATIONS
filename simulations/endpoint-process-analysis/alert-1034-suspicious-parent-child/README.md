# Alert 1034 — Suspicious Parent–Child Relationship

> TryHackMe simulated SOC investigation | Analyst: Ayobami Odulaja  
> Status: **Under investigation** | Updated: 2026-10-13

## Investigation summary

I began triaging a high-severity process alert on win-3450. The supplied Sysmon process-creation event records PowerShell launching nslookup with an encoded-looking subdomain of haz4rdw4re[.]io. I identified possible DNS-based data transfer as a hypothesis and prepared process and domain pivots for further investigation. A final verdict has not been established.

This case documents a training environment, not a production incident.

## Observed evidence

| Field | Value |
|---|---|
| Alert ID / title | 1034 / Suspicious Parent Child Relationship |
| Platform severity | High |
| Alert display time | October 9, 2026, 16:45 |
| Event timestamp | October 9, 2026, 16:43:27.514; timezone not supplied |
| Data source / event code | Sysmon / 1 |
| Host | win-3450 |
| Child process / PID | nslookup.exe / 3648 |
| Parent process / PID | powershell.exe / 3728 |
| Executable path | C:\Windows\system32\nslookup.exe |
| Working directory | C:\Users\michael.ascot\downloads\ |
| Domain | haz4rdw4re[.]io |
| Event action | Process Create (rule: ProcessCreate) |

The screenshot preserves the full command line and encoded-looking query label. This label has not yet been independently extracted or decoded.

## Evidence screenshot

![Alert 1034 showing PowerShell launching nslookup](screenshots/01-alert-1034-process-creation.png)

*Figure 1. Initial alert details. The username and host shown are simulation artifacts.*

## Analysis and confidence

- **Observed:** PowerShell created an nslookup process with the command line shown in Figure 1.
- **Hypothesis:** The query label may contain encoded data intended for transfer through DNS.
- **Alternative explanation:** Authorized automation, troubleshooting, or a security exercise could produce this process relationship.
- **Unconfirmed:** PowerShell origin, script contents, query repetition, DNS responses, transmitted data, authorization, and activity on other hosts.

A process-creation event demonstrates execution of the command, but does not establish successful DNS resolution or completed exfiltration. Missing telemetry must be recorded as a visibility gap, not treated as proof of benign activity.

## Investigation pivots — prepared, not yet executed

Start with October 9, 2026, 16:30–17:00 in the SIEM's displayed timezone. Confirm time alignment before correlating other sources. These field-based searches assume the interface supports the displayed fields and syntax; adjust after examining the SIEM.

### Host activity

~~~text
host.name:"win-3450"
~~~

### Parent and child process activity

~~~text
host.name:"win-3450" AND (process.pid:3728 OR process.pid:3648 OR process.parent.pid:3728)
~~~

Use process GUIDs and timestamps where available to avoid correlating unrelated events after PID reuse.

### Domain scope

~~~text
"haz4rdw4re.io"
~~~

## Next evidence required

1. Retrieve the parent PowerShell creation event and full command line; identify its parent and user context.
2. Review script execution telemetry if available and identify any referenced script or input file.
3. Correlate DNS queries and responses with process identity and timestamps; assess repeated or changing labels.
4. Extract the query label exactly and decode offline without executing recovered content.
5. Search other hosts for the same domain and related activity.
6. Establish whether the activity was authorized before assigning the final classification.

## Disposition and response

**Verdict: Pending.** No containment, domain blocking, escalation, or remediation has been performed or verified in this case.

If additional evidence substantiates malicious activity, recommend escalation, host containment, evidence preservation, and domain blocking under the applicable playbook. Record proposed actions separately from actions actually performed.

## Skills demonstrated

Initial alert triage, process lineage review, command-line analysis, hypothesis formation, SIEM pivot preparation, and evidence-led documentation.

## Learning point

An uncommon process relationship is a starting point for investigation. A defensible verdict depends on correlated evidence and explicit acknowledgement of visibility gaps.
