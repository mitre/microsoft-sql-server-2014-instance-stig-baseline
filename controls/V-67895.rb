control "V-67895" do
  title "SQL Server or software monitoring SQL Server must provide an immediate
real-time alert to appropriate support staff of all audit failure events
requiring real-time alerts."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without a real-time
alert, security personnel may be unaware of an impending failure of the audit
capability, and system operation may be adversely affected.

    As noted elsewhere in this document, SQL Server's Audit and/or Trace
features can be used for auditing purposes.  This requirement applies to both.

    The appropriate support staff include, at a minimum, the ISSO and the
DBA/SA.

    Alerts provide organizations with urgent messages. Real-time alerts provide
these messages immediately (i.e., the time from event detection to alert occurs
in seconds or less).
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000360-DB-000320"
  tag "gid": "V-67895"
  tag "rid": "SV-82385r1_rule"
  tag "stig_id": "SQL4-00-033500"
  tag "fix_id": "F-74011r1_fix"
  tag "cci": ["CCI-001858"]
  tag "nist": ["AU-5 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the system documentation to determine which audit
failure events require real-time alerts.

Review settings in SQL Server, Windows, and any monitoring software. If the
real-time alerting that is specified in the documentation is not enabled, this
is a finding."
  tag "fix": "Configure the system to provide an immediate real-time alert to
appropriate support staff when a specified audit failure occurs."
end

