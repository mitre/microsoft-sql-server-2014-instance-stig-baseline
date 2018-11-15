control 'V-67803' do
  title "SQL Server and/or the operating system must protect its audit
  configuration from unauthorized modification."
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data. Therefore, protecting audit tools
  is necessary to prevent unauthorized operation on audit data.

      Applications providing tools to interface with audit data will leverage
  user permissions and roles identifying the user accessing the tools and the
  corresponding rights the user enjoys in order make access decisions regarding
  the modification of audit tools.

      Audit tools include, but are not limited to, vendor-provided and open
  source audit tools needed to successfully view and manipulate audit information
  system activity and records. Audit tools include custom queries and report
  generators.

      This focuses on external tools for log maintenance and review.  Other STIG
  requirements govern SQL Server privileges to maintain trace or audit
  definitions.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000122-DB-000203'
  tag "gid": 'V-67803'
  tag "rid": 'SV-82293r1_rule'
  tag "stig_id": 'SQL4-00-014000'
  tag "fix_id": 'F-73919r1_fix'
  tag "cci": ['CCI-001494']
  tag "nist": ['AU-9', 'Rev_4']
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
  tag "check": "In Windows, review the access permissions to tools used to view
  or modify audit log data (to include traces used for audit purposes).

  If appropriate permissions and access controls to prevent unauthorized changes
  are not applied to these tools, this is a finding."
  tag "fix": "Apply or modify Windows permissions on tools used to view or
  modify audit log data (to include traces used for audit purposes), to make them
  accessible by authorized personnel only."
  describe "SQL Server and/or the operating system must protect its audit
  configuration from unauthorized modification." do
    skip 'This control is manual'
  end
end
