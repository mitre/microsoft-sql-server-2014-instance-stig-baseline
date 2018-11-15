APPROVED_USERS_SERVER = attribute('approved_users_server')

APPROVED_USERS_DATABASE = attribute('approved_users_database')

control 'V-67815' do
  title "The role(s)/group(s) used to modify database structure (including but
  not necessarily limited to tables, indexes, storage, etc.) and logic modules
  (stored procedures, functions, triggers, links to software external to SQL
  Server, etc.) must be restricted to authorized users."
  desc "If SQL Server were to allow any user to make changes to database
  structure or logic, then those changes might be implemented without undergoing
  the appropriate testing and approvals that are part of a robust change
  management process.

      Accordingly, only qualified and authorized individuals shall be allowed to
  obtain access to information system components for purposes of initiating
  changes, including upgrades and modifications.

      Unmanaged changes that occur to the database software libraries or
  configuration can lead to unauthorized or compromised installations.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000133-DB-000362'
  tag "gid": 'V-67815'
  tag "rid": 'SV-82305r1_rule'
  tag "stig_id": 'SQL4-00-030700'
  tag "fix_id": 'F-73931r1_fix'
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
  tag "check": "Using the system security plan, identify the group(s)/role(s)
  established for SQL Server DBMS and database modification, and the individuals
  authorized to modify the DBMS and database(s).  If helpful, the views
  STIG.server_permissions and STIG.database_permissions, provided in the
  supplemental file Permissions.sql, can be used to search for the relevant
  roles:  look for Permission values containing \"Alter,\" \"Create,\"
  \"Control,\" etc.

  Obtain the list of users in those group(s)/roles.  The provided functions
  STIG.members_of_db_role() and ;, can be used for
  this.

  If unauthorized access to the group(s)/role(s) has been granted, this is a
  finding."
  tag "fix": "Revoke unauthorized memberships in the group(s)/role(s)
  designated for DBMS and database modification.

  Syntax examples:

  ALTER ROLE Power DROP MEMBER JenUser; -- the member is a database role or
  database user.
  ALTER SERVER ROLE GreatPower DROP MEMBER Irresponsibility; -- the member is a
  server role or login."
  # permissions_server = command("Invoke-Sqlcmd -Query \"SELECT Grantee, Permission FROM STIG.server_permissions WHERE Permission LIKE '%CONTROL%' OR Permission LIKE '%alter%' OR Permission LIKE '%create%'\" -ServerInstance '#{SERVER_INSTANCE}' | Findstr /v 'Grantee ---'").stdout.strip.split("\n")

  sql = mssql_session(user: attribute('user'),
                      password: attribute('password'),
                      host: attribute('host'),
                      instance: attribute('instance'),
                      port: attribute('port'))
  permissions_server = sql.query("SELECT Grantee as result FROM STIG.server_permissions WHERE Permission LIKE '%CONTROL%' OR Permission LIKE '%alter%' OR Permission LIKE '%create%';").column('result')

  if  permissions_server.empty?
    impact 0.0
    desc 'There are no sql audit permissions alter any server audit granted control not applicable'

    describe 'There are no sql audit permissions alter any server audit granted, control not applicable' do
      skip 'There are no sql audit permissions  alter any server audit granted, control not applicable'
    end
  else
    permissions_server.each do |grantee|
      a = grantee.strip
      describe "sql audit server permissions: #{a}" do
        subject { a }
        it { should be_in APPROVED_USERS_SERVER }
      end
    end
  end

  permissions_database = sql.query("SELECT Grantee as result FROM STIG.database_permissions WHERE Permission LIKE '%CONTROL%' OR Permission LIKE '%alter%' OR Permission LIKE '%create%';").column('result')

  if  permissions_database.empty?
    impact 0.0
    desc 'There are no sql audit permissions alter any server audit granted control not applicable'

    describe 'There are no sql audit permissions alter any server audit granted, control not applicable' do
      skip 'There are no sql audit permissions  alter any server audit granted, control not applicable'
    end
  else
    permissions_database.each do |grantee|
      a = grantee.strip
      describe "sql audit permissions alter any server audit: #{a}" do
        subject { a }
        it { should be_in APPROVED_USERS_DATABASE }
      end
    end
  end
end
