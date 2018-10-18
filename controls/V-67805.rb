APPROVED_USERS_SQL_AUDIT_FEATURES = attribute(
  'approved_users_sql_audit_features',
  description: 'List of approved audit permissions',
  default: ["SERVER_AUDIT_MAINTAINERS                                    ALTER ANY SERVER AUDIT"]
)

SERVER_INSTANCE= attribute(
  'server_instance',
  description: 'SQL server instance we are connecting to',
  default: "WIN-FC4ANINFUFP"
) 


control "V-67805" do
  title "SQL Server and the operating system must protect SQL Server audit
  features from unauthorized removal."
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data. Therefore, protecting audit tools
  is necessary to prevent unauthorized operation on audit data.

      Applications providing tools to interface with audit data will leverage
  user permissions and roles identifying the user accessing the tools and the
  corresponding rights the user enjoys in order make access decisions regarding
  the deletion of audit tools.

      Audit tools include, but are not limited to, vendor-provided and open
  source audit tools needed to successfully view and manipulate audit information
  system activity and records. Audit tools include custom queries and report
  generators.

      This focuses on external tools for log maintenance and review.  Other STIG
  requirements govern SQL Server privileges to maintain trace or audit
  definitions.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000123-DB-000204"
  tag "gid": "V-67805"
  tag "rid": "SV-82295r1_rule"
  tag "stig_id": "SQL4-00-014100"
  tag "fix_id": "F-73921r1_fix"
  tag "cci": ["CCI-001495"]
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
  tag "check": "In Windows, review the access permissions to tools used to view
  or modify audit log data (to include traces used for audit purposes).

  If appropriate permissions and access controls to prevent unauthorized
  deletions are not applied to these tools, this is a finding."
  tag "fix": "Apply or modify Windows permissions on tools used to view or
  modify audit log data (to include traces used for audit purposes), to make them
  accessible by authorized personnel only."
  permissions = command("Invoke-Sqlcmd -Query \"SELECT login.name, perm.permission_name FROM sys.server_permissions perm  JOIN sys.server_principals login ON perm.grantee_principal_id = login.principal_id WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT') and login.name not like '##MS_%'; \" -ServerInstance '#{SERVER_INSTANCE}' | Findstr /v 'name ---'").stdout.strip.split("\n")
  permissions.each do | perms|  
    a = perms.strip
    describe "#{a}" do
      it { should be_in APPROVED_USERS_SQL_AUDIT_FEATURES}
    end  
  end 
end

