control 'V-67809' do
  title "SQL Server security-relevant configuration settings must be monitored
  to discover unauthorized changes."
  desc "When dealing with change control issues, it should be noted, any
  changes to security-relevant configuration settings of SQL Server can
  potentially have significant effects on the overall security of the system.

      If SQL Server were to allow any user to make changes to configuration
  settings, then those changes might be implemented without undergoing the
  appropriate testing and approvals that are part of a robust change management
  process. This requirement is contingent upon the configuration of SQL Server's
  hosted application and the security-relevant configuration settings of SQL
  Server.

      Accordingly, only qualified and authorized individuals shall be allowed to
  obtain access to these security-relevant configuration settings for purposes of
  initiating changes, including upgrades and modifications.

      Unmanaged changes that occur to SQL Server software libraries or
  configuration can lead to unauthorized or compromised installations.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000133-DB-000179'
  tag "gid": 'V-67809'
  tag "rid": 'SV-82299r1_rule'
  tag "stig_id": 'SQL4-00-015300'
  tag "fix_id": 'F-73925r1_fix'
  tag "cci": ['CCI-001499']
  tag "nist": ['CM-5 (6)', 'Rev_4']
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
  tag "check": "Verify within the system documentation that SQL Server is
  monitored for security-relevant configuration settings to discover unauthorized
  changes.

  This can be done by a third-party tool or a SQL script that does baselining and
  then comparisons.

  If the monitoring of security-relevant configuration settings to discover
  unauthorized changes is not implemented on SQL Server, this is a finding."
  tag "fix": "Document the monitoring of security-relevant configuration
  settings to discover unauthorized changes within the system documentation.

  Document the specific users or types of security personnel that are able to
  monitor security-relevant configuration settings to discover unauthorized
  changes.

  Deploy and implement a third-party tool or some other SQL Server method of
  monitoring security-relevant configuration settings to discover unauthorized
  changes."
  describe "SQL Server security-relevant configuration settings must be monitored
  to discover unauthorized changes." do
    skip 'This control is manual'
  end
end
