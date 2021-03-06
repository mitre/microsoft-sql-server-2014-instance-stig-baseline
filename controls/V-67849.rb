control 'V-67849' do
  title 'SQL Server must have the Filestream feature disabled if it is unused.'
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by default
  or selected for installation by an administrator, may not be necessary to
  support essential organizational operations (e.g., key missions, functions).

      Applications must adhere to the principles of least functionality by
  providing only essential capabilities.  Unused and unnecessary SQL Server
  components increase the number of available attack vectors.  By minimizing the
  services and applications installed on the system, the number of potential
  vulnerabilities is reduced.

      The Filestream feature must be disabled if it is unused.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000141-DB-000091'
  tag "gid": 'V-67849'
  tag "rid": 'SV-82339r1_rule'
  tag "stig_id": 'SQL4-00-016855'
  tag "fix_id": 'F-73965r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
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
  tag "check": "Determine whether Filestream is required to support the
  database(s) in this instance of SQL Server.

  Either, in SQL Server Management Studio, Object Explorer, right-click on the
  SQL Server instance; select Properties; examine the Filestream section.

  If Filestream Access Level is \"Disabled\", this is not a finding.

  If Filestream Access Level is \"Transact-SQL access enabled\" or \"Full access
  enabled,\" and Filestream is not required, this is a finding.

  If Filestream Access Level is \"Full access enabled,\" but only Transact-SQL
  access is required, this is a finding.

  Or, in a query tool, run this code:
       EXEC sys.sp_configure N'filestream access level';

  Review the number in the config_value column.  If it is 0, this is not a
  finding. 

  If config_value is 1 or 2, and Filestream is not required, this is a finding.

  If config_value is 2, but only Transact-SQL access is required, this is a
  finding."
  tag "fix": "Either, in SQL Server Management Studio, Object Explorer,
  right-click on the SQL Server instance; select Properties; examine the
  Filestream section.

  If Filestream is not required, set Filestream Access Level to \"Disabled.\"

  If Filestream is required only at the Transact-SQL query level, set Filestream
  Access Level to \"Transact-SQL access enabled.\"

  Restart the SQL Server instance.

  Or, in a query tool, run this script, substituting the correct value for
  <Level>:
       EXEC sys.sp_configure N'filestream access level', N'<Level>';
       GO
       RECONFIGURE WITH OVERRIDE;
       GO

  The <Level> values are:
  0 - Disabled
  1 - Transact-SQL access enabled
  2 - Full access enabled"


  filestream_required = attribute('filestream_required')

  filestream_transact_access_only_required = attribute('filestream_transact_access_only_required')

  query = %(
    EXEC sys.sp_configure N'filestream access level';
  )
  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              db_name: attribute('db_name'))
  if !filestream_required
    describe 'The filestream access level' do
      subject { sql_session.query(query).column('config_value') }
      it { should cmp 0 }
    end
  end
  if filestream_transact_access_only_required
    describe 'The filestream access level' do
      subject { sql_session.query(query).column('config_value') }
      it { should_not cmp 2 }
    end
  end
end
