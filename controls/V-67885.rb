ALLOWED_USERS = attribute('allowed_users')

control 'V-67885' do
  title "SQL Server must prevent non-privileged users from executing privileged
  functionality, to include disabling, circumventing, or altering implemented
  security safeguards/countermeasures."
  desc "Preventing non-privileged users from executing privileged functions
  mitigates the risk that unauthorized individuals or processes may gain
  unnecessary access to information or privileges.

      System documentation should include a definition of the functionality
  considered privileged.

      Depending on circumstances, privileged functions can include, for example,
  establishing accounts, performing system integrity checks, or administering
  cryptographic key management activities. Non-privileged users are individuals
  that do not possess appropriate authorizations. Circumventing intrusion
  detection and prevention mechanisms or malicious code protection mechanisms are
  examples of privileged functions that require protection from non-privileged
  users.

      A privileged function in the DBMS/database context is any operation that
  modifies the structure of the database, its built-in logic, or its security
  settings. This would include all Data Definition Language (DDL) statements and
  all security-related statements. In SQL Server, it encompasses, but is not
  necessarily limited to:
      CREATE
      ALTER
      DROP
      GRANT
      REVOKE
      DENY

      There may also be Data Manipulation Language (DML) statements that, subject
  to context, should be regarded as privileged. Possible examples include:

      TRUNCATE TABLE;
      DELETE, or
      DELETE affecting more than n rows, for some n, or
      DELETE without a WHERE clause;

      UPDATE or
      UPDATE affecting more than n rows, for some n, or
      UPDATE without a WHERE clause;

      any SELECT, INSERT, UPDATE, or DELETE to an application-defined security
  table executed by other than a security principal.

      Depending on the design of the database and associated applications, the
  prevention of unauthorized use of privileged functions may be achieved by means
  of DBMS security features, database triggers, other mechanisms, or a
  combination of these.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000340-DB-000304'
  tag "gid": 'V-67885'
  tag "rid": 'SV-82375r1_rule'
  tag "stig_id": 'SQL4-00-032500'
  tag "fix_id": 'F-74001r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
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
  tag "check": "Review the system documentation to obtain the definition of the
  SQL Server database/DBMS functionality considered privileged in the context of
  the system in question.

  Review the SQL Server security configuration and/or other means used to protect
  privileged functionality from unauthorized use.

  If the configuration does not protect all of the actions defined as privileged,
  this is a finding.

  The database permission functions and views provided in the supplemental file
  Permissions.sql can help with this."
  tag "fix": "Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER
  ... statements to align EXECUTE permissions (and any other relevant
  permissions) with documented requirements."

  sql = mssql_session(user: attribute('user'),
                      password: attribute('password'),
                      host: attribute('host'),
                      instance: attribute('instance'),
                      port: attribute('port'))
  permissions = sql.query("SELECT Grantee as 'result' FROM STIG.database_permissions WHERE Permission LIKE '%CREATE%' OR Permission LIKE '%ALTER%'").column('result')

  if  permissions.empty?
    impact 0.0
    desc 'There are no sql privileged users, control not applicable'

    describe 'There are no sql privileged users, control not applicable' do
      skip 'There are no sql privileged users, control not applicable'
    end
  else
    permissions.each do |perms|
      a = perms.strip
      describe "sql privileged users: #{a}" do
        subject { a }
        it { should be_in ALLOWED_USERS }
      end
    end

  end
end
