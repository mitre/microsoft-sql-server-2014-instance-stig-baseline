ALLOWED_USERS_PRIV_FUNCTIONS = attribute('allowed_users_priv_functions')

control 'V-67899' do
  title "SQL Server must prohibit user installation of logic modules (stored
  procedures, functions, triggers, views, etc.) without explicit privileged
  status."
  desc "Allowing regular users to install software, without explicit
  privileges, creates the risk that untested or potentially malicious software
  will be installed on the system. Explicit privileges (escalated or
  administrative privileges) provide the regular user with explicit capabilities
  and control that exceed the rights of a regular user.

      The nature and requirements of databases will vary; so while users are not
  permitted to install unapproved software, there may be instances where the
  organization allows the user to install approved software packages such as from
  an approved software repository. The requirements for production servers will
  be more restrictive than those used for development and research.

      SQL Server must control software installation by users based upon what
  types of software installations are permitted (e.g., updates and security
  patches to existing software) and what types of installations are prohibited
  (e.g., software whose pedigree with regard to being potentially malicious is
  unknown or suspect) by the organization).

      In the case of a database management system, this requirement covers stored
  procedures, functions, triggers, views, etc.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000378-DB-000365'
  tag "gid": 'V-67899'
  tag "rid": 'SV-82389r1_rule'
  tag "stig_id": 'SQL4-00-033800'
  tag "fix_id": 'F-74015r1_fix'
  tag "cci": ['CCI-001812']
  tag "nist": ['CM-11 (2)', 'Rev_4']
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
  tag "check": "If the SQL Server instance supports only software development,
  experimentation and/or developer-level testing (that is, excluding production
  systems, integration testing, stress testing, and user acceptance testing),
  this is not a finding.

  Review the SQL Server instance and database security settings with respect to
  non-administrative users' ability to create, alter, or replace logic modules,
  to include but not necessarily only stored procedures, functions, triggers, and
  views.  The database permission functions and views provided in the
  supplemental file Permissions.sql can help with this.

  If any such permissions exist and are not documented and approved, this is a
  finding."
  tag "fix": "Document and obtain approval for any non-administrative users who
  require the ability to create, alter or replace logic modules.

  Implement the approved permissions. Revoke (or Deny) any unapproved
  permissions, and remove any unauthorized role memberships."

  sql = mssql_session(user: attribute('user'),
                      password: attribute('password'),
                      host: attribute('host'),
                      instance: attribute('instance'),
                      port: attribute('port'))
  permissions = sql.query("SELECT Grantee as 'result' FROM STIG.database_permissions WHERE Permission LIKE '%CREATE%' OR Permission LIKE '%ALTER%' OR Permission LIKE '%DELETE%'").column('result')
  if  permissions.empty?
    impact 0.0
    desc 'There are no sql privileged database users, control not applicable'

    describe 'There are no sql privileged database users, control not applicable' do
      skip 'There are no sql privileged database users, control not applicable'
    end
  else
    permissions.each do |perms|
      a = perms.strip
      describe "sql privileged database users: #{a}" do
        subject { a }
        it { should be_in ALLOWED_USERS_PRIV_FUNCTIONS }
      end
    end

  end
end
