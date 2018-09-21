control "V-67893" do
  title "SQL Server, the operating system, or the storage system must provide a
  warning to appropriate support staff when allocated audit record storage volume
  reaches 75% of maximum audit record storage capacity."
  desc  "Organizations are required to use a central log management system, so,
  under normal conditions, the audit space allocated to SQL Server on its own
  server will not be an issue. However, space will still be required on the DBMS
  server for audit records in transit, and, under abnormal conditions, this could
  fill up. Since a requirement exists to halt processing upon audit failure, a
  service outage would result.

      As noted elsewhere in this document, SQL Server's Audit and/or Trace
  features can be used for auditing purposes.  This requirement applies to both.

      If support personnel are not notified immediately upon storage volume
  utilization reaching 75%, they are unable to plan for storage capacity
  expansion.

      The monitoring and alerting may be done at the database level, the
  operating system level, or by specialized monitoring tools.

      The appropriate support staff include, at a minimum, the ISSO and the
  DBA/SA.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000359-DB-000319"
  tag "gid": "V-67893"
  tag "rid": "SV-82383r1_rule"
  tag "stig_id": "SQL4-00-033400"
  tag "fix_id": "F-74009r1_fix"
  tag "cci": ["CCI-001855"]
  tag "nist": ["AU-5 (1)", "Rev_4"]
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
  tag "check": "Review system configuration.

  If appropriate support staff are not notified immediately upon storage volume
  utilization reaching 75%, this is a finding."
  tag "fix": "Configure the system to notify appropriate support staff
  immediately upon storage volume utilization reaching 75%."
end

