control "V-67855" do
  title "SQL Server default account [sa] must have its name changed."
  desc  "SQL Server's [sa] account has special privileges required to
  administer the database. The [sa] account is a well-known SQL Server account
  name and is likely to be targeted by attackers, and is thus more prone to
  providing unauthorized access to the database.

      Since the SQL Server [sa] is administrative in nature, the compromise of a
  default account can have catastrophic consequences, including the complete loss
  of control over SQL Server. Since SQL Server needs for this account to exist
  and it should not be removed, one way to mitigate this risk is to change the
  [sa] account name.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000141-DB-000092"
  tag "gid": "V-67855"
  tag "rid": "SV-82345r1_rule"
  tag "stig_id": "SQL4-00-010200"
  tag "fix_id": "F-73971r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "Verify the SQL Server default [sa] (system administrator)
  account name has been changed by executing the following query:

  USE master;
  GO
  SELECT *
  FROM sys.sql_logins
  WHERE [name] = 'sa' OR [principal_id] = 1;
  GO

  If the login account name \"SA\" or \"sa\" appears in the query output, this is
  a finding."
  tag "fix": "Modify the SQL Server's [sa] (system administrator) account by
  running the following script:

  USE master;
  GO
  ALTER LOGIN [sa] WITH NAME = <new name>;
  GO"
  describe.one do
    describe command("Invoke-Sqlcmd -Query \"SELECT * FROM sys.sql_logins WHERE [name] = 'sa'\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT * FROM sys.sql_logins WHERE [name] = 'SA'\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should eq '' }
    end
  end
end

