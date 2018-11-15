ALLOWED_SQL_ALTER_PERMISSIONS = attribute('allowed_sql_alter_permissions')

control 'V-67795' do
  title "SQL Server must protect its audit features from unauthorized access,
  modification, or removal."
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data.

      Depending upon the log format and application, system and application log
  tools may provide the only means to manipulate and manage application and
  system log data. It is, therefore, imperative that access to audit tools be
  controlled and protected from unauthorized access.

      If an attacker were to gain access to audit tools, he could analyze audit
  logs for system weaknesses or weaknesses in the auditing itself. An attacker
  could also manipulate logs to hide evidence of malicious activity.

      This focuses on audit/trace log tools within SQL Server.  Other STIG
  requirements govern operating system settings to control access to external
  tools.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000121-DB-000202'
  tag "gid": 'V-67795'
  tag "rid": 'SV-82285r1_rule'
  tag "stig_id": 'SQL4-00-013900'
  tag "fix_id": 'F-73911r1_fix'
  tag "cci": ['CCI-001493']
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
  tag "check": "Review the SQL Server permissions granted to principals.  The
  views and functions provided in the supplemental file Permissions.sql can help
  with this.  Look for permissions such as ALTER ANY SERVER AUDIT, ALTER ANY
  DATABASE AUDIT, ALTER TRACE; or EXECUTE on the stored procedures with names
  beginning \"SP_TRACE\", or on scopes including those procedures.

  If unauthorized accounts have these privileges, this is a finding."
  tag "fix": "Use REVOKE and/or DENY statements to remove audit-related
  permissions from individuals and roles not authorized to have them."

  sql = mssql_session(user: attribute('user'),
                      password: attribute('password'),
                      host: attribute('host'),
                      instance: attribute('instance'),
                      port: attribute('port'))
  permissions = sql.query("SELECT Grantee as result FROM STIG.server_permissions P WHERE
        P.[Permission] IN
        (
        'ALTER ANY SERVER AUDIT',
        'ALTER ANY DATABASE',
        'ALTER TRACE',
        'EXECUTE'
        );").column('result')

  if  permissions.empty?
    impact 0.0

    describe "There are no sql audit permissions ALTER ANY SERVER AUDIT, ALTER ANY
      DATABASE AUDIT, ALTER TRACE; or EXECUTE granted, control not applicable" do
      skip "There are no sql audit permissions  ALTER ANY SERVER AUDIT, ALTER ANY
      DATABASE AUDIT, ALTER TRACE; or EXECUTEgranted, control not applicable"
    end
  else
    permissions.each do |grantee|
      a = grantee.strip
      describe "sql audit permissions ALTER ANY SERVER AUDIT, ALTER ANY
  DATABASE AUDIT, ALTER TRACE; or EXECUTE: #{a}" do
        subject { a }
        it { should be_in ALLOWED_SQL_ALTER_PERMISSIONS }
      end
    end
  end
end
