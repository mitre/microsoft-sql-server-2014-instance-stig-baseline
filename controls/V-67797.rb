APPROVED_USERS_SQL_AUDITS = attribute(
  'approved_users_sql_audits',
  description: 'List of approved audit permissions',
  default: ["##MS_PolicySigningCertificate##                             CONTROL SERVER",
            "SERVER_AUDIT_MAINTAINERS                ALTER ANY SERVER AUDIT                  GRANT",
            "SERVER_AUDIT_MAINTAINERS                ALTER TRACE                             GRANT"]
)

SERVER_INSTANCE= attribute(
  'server_instance',
  description: 'SQL server instance we are connecting to',
  default: "WIN-FC4ANINFUFP"
)

control "V-67797" do
  title "SQL Server Profiler must be protected  from unauthorized access,
  modification, or removal."
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data.  SQL Server Profiler is one such
  tool.

    If an attacker were to gain access to audit tools, he could analyze audit
  logs for system weaknesses or weaknesses in the auditing itself. An attacker
  could also manipulate logs to hide evidence of malicious activity.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000121-DB-000202"
  tag "gid": "V-67797"
  tag "rid": "SV-82287r2_rule"
  tag "stig_id": "SQL4-00-013910"
  tag "fix_id": "F-73913r2_fix"
  tag "cci": ["CCI-001493"]
  tag "nist": ["AU-9", "Rev_4"]
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
  tag "check": "Check the server documentation for a list of approved users
  with access to SQL Server Audits.

  To create, alter, or drop a server audit, principals require the ALTER ANY
  SERVER AUDIT or the CONTROL SERVER permission.  To view an Audit log requires
  the CONTROL SERVER permission.  To use Profiler, ALTER TRACE is required.

  Review the SQL Server permissions granted to principals. Look for permissions
  ALTER ANY SERVER AUDIT, ALTER ANY DATABASE AUDIT, CONTROL SERVER, ALTER TRACE:

  SELECT login.name, perm.permission_name, perm.state_desc
  FROM sys.server_permissions perm
  JOIN sys.server_principals login
  ON perm.grantee_principal_id = login.principal_id
  WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER
  ANY SERVER AUDIT','ALTER TRACE')
  and login.name not like '##MS_%';

  If unauthorized accounts have these privileges, this is a finding. "
  tag "fix": "Remove audit-related permissions from individuals and roles not
  authorized to have them.

  USE master;
  DENY [ALTER ANY SERVER AUDIT] TO [User];
  GO"
  permissions = command("Invoke-Sqlcmd -Query \"SELECT login.name, perm.permission_name, perm.state_desc FROM sys.server_permissions perm JOIN sys.server_principals login ON perm.grantee_principal_id = login.principal_id WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE') and login.name not like '##MS_%';\" -ServerInstance '#{SERVER_INSTANCE}' | Findstr /v 'Grantee name ---'").stdout.strip.split("\n")
  permissions.each do | perms|  
    a = perms.strip
    describe "#{a}" do
      it { should be_in APPROVED_USERS_SQL_AUDITS }
    end  
  end 
end

