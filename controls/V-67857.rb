control 'V-67857' do
  title "Access to xp_cmdshell must be disabled, unless specifically required
  and approved."
  desc "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

      It is detrimental for applications to provide, or install by default,
  functionality exceeding requirements or mission objectives.

      Applications must adhere to the principles of least functionality by
  providing only essential capabilities.

      DBMSs may spawn additional external processes to execute procedures that
  are defined in the DBMS, but stored in external host files (external
  procedures). The spawned process used to execute the external procedure may
  operate within a different OS security context than the DBMS and provide
  unauthorized access to the host system.

      The xp_cmdshell extended stored procedure allows execution of host
  executables outside the controls of database access permissions. This access
  may be exploited by malicious users who have compromised the integrity of the
  SQL Server database process to control the host operating system to perpetrate
  additional malicious activity.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000141-DB-000093'
  tag "gid": 'V-67857'
  tag "rid": 'SV-82347r1_rule'
  tag "stig_id": 'SQL4-00-017200'
  tag "fix_id": 'F-73973r1_fix'
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
  tag "check": "To determine if xp_cmdshell is enabled, execute the following
  commands:

       EXEC SP_CONFIGURE 'show advanced options', '1';
       RECONFIGURE WITH OVERRIDE;
       EXEC SP_CONFIGURE 'xp_cmdshell';

  If the value of config_value is 0, this is not a finding.

  Review the system documentation to determine whether the use of xp_cmdshell is
  required and approved.  If it is not approved, this is a finding."
  tag "fix": "To disable the use of xp_cmdshell, from the query prompt:
  EXEC sp_configure 'show advanced options', 1;
  GO
  RECONFIGURE;
  GO
  EXEC sp_configure 'xp_cmdshell', 0;
  GO
  RECONFIGURE;
  GO"

  query = %(
     EXEC sys.sp_configure N'xp_cmdshell';
  )

  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'))

  is_xp_cmdshell_required = attribute('is_xp_cmdshell_required')

  describe.one do
    describe 'Is xp cmdshell required' do
      subject { is_xp_cmdshell_required }
      it { should be true }
    end
    describe 'The xp_cmdshell config_value' do
      subject { sql_session.query(query).column('config_value').uniq }
      it { should cmp 0 }
    end
  end
end
