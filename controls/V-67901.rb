ALLOWED_SERVER_PERMISSIONS = attribute('allowed_server_permissions')

ALLOWED_DATABASE_PERMISSIONS = attribute('allowed_database_permissions')

control 'V-67901' do
  title "SQL Server and Windows must enforce access restrictions associated
  with changes to the configuration of the SQL Server instance or database(s)."
  desc "Failure to provide logical access restrictions associated with changes
  to configuration may have significant effects on the overall security of the
  system.

      When dealing with access restrictions pertaining to change control, it
  should be noted that any changes to the hardware, software, and/or firmware
  components of the information system can potentially have significant effects
  on the overall security of the system.

      Accordingly, SQL Server and Windows must allow only qualified and
  authorized individuals to obtain access to system components for the purposes
  of initiating changes, including upgrades and modifications.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000380-DB-000360'
  tag "gid": 'V-67901'
  tag "rid": 'SV-82391r1_rule'
  tag "stig_id": 'SQL4-00-033900'
  tag "fix_id": 'F-74017r1_fix'
  tag "cci": ['CCI-001813']
  tag "nist": ['CM-5 (1)', 'Rev_4']
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
  tag "check": "Review the security configuration of the SQL Server instance
  and database(s).

  If unauthorized Windows users can start the SQL Server Configuration Manager or
  SQL Server Management Studio, this is a finding.

  If SQL Server does not enforce access restrictions associated with changes to
  the configuration of the SQL Server instance or database(s), this is a finding.

  - - - - -

  To assist in conducting reviews of permissions, the following views and
  permissions are defined in the supplemental file Permissions.sql, provided with
  this STIG:
  database_permissions
  database_role_members
  server_permissions
  server_role_members
  database_effective_permissions('<database user/role name>')
  database_roles_of('<database user/role name>')
  members_of_db_role('<database role name>')
  members_of_server_role('<server role name>')
  server_effective_permissions('<server login/role name>')
  server_roles_of('<server login/role name>')

  Permissions of concern in this respect include the following, and possibly
  others:
  - any server permission except CONNECT SQL, but including CONNECT ANY DATABASE
  - any database permission beginning with \"CREATE\" or \"ALTER\"
  - CONTROL
  - INSERT, UPDATE, DELETE, EXECUTE on locally-defined tables and procedures
  designed for supplemental configuration and security purposes."
  tag "fix": "Configure SQL Server to enforce access restrictions associated
  with changes to the configuration of the SQL Server instance and database(s)."

  sql = mssql_session(user: attribute('user'),
                      password: attribute('password'),
                      host: attribute('host'),
                      instance: attribute('instance'),
                      port: attribute('port'))

  get_server_permissions = sql.query("SELECT DISTINCT Grantee as 'result' FROM STIG.server_permissions WHERE Permission != 'CONNECT SQL';").column('result')
  get_server_permissions.each do |server_perms|
    a = server_perms.strip
    describe "sql server permissions: #{a}" do
      subject { a }
      it { should be_in ALLOWED_SERVER_PERMISSIONS }
    end
  end

  get_database_permissions = sql.query("SELECT DISTINCT Grantee as 'result' FROM STIG.database_permissions WHERE Permission LIKE '%CREATE%' OR Permission LIKE '%ALTER%' OR Permission IN ('CONTROL', 'INSERT', 'UPDATE', 'DELETE', 'EXECUTE');").column('result')
  get_database_permissions.each do |database_perms|
    a = database_perms.strip
    describe a.to_s do
      it { should be_in ALLOWED_DATABASE_PERMISSIONS }
    end
    describe "sql database permissions: #{a}" do
      subject { a }
      it { should be_in ALLOWED_DATABASE_PERMISSIONS }
    end
  end

  if get_server_permissions.empty? || get_database_permissions 
    impact 0.0
    describe "There are no server or database permissions of concern configured" do
      skip "This control is not applicable"
    end
  end
end
