
control 'V-67765' do
  title "Where SQL Server Trace is in use for auditing purposes, SQL Server
  must allow only the ISSM (or individuals or roles appointed by the ISSM) to
  select which auditable events are to be traced."
  desc "Without the capability to restrict which roles and individuals can
  select which events are audited, unauthorized personnel may be able to prevent
  or interfere with the auditing of critical events.

      Suppression of auditing could permit an adversary to evade detection.

      Misconfigured audits can degrade the system's performance by overwhelming
  the audit log. Misconfigured audits may also make it more difficult to
  establish, correlate, and investigate the events relating to an incident or
  identify those responsible for one.

      Use of SQL Server Audit is recommended.  All features of SQL Server Audit
  are available in the Enterprise and Developer editions of SQL Server 2014.  It
  is not available at the database level in other editions.  For this or legacy
  reasons, the instance may be using SQL Server Trace for auditing, which remains
  an acceptable solution for the time being.  Note, however, that Microsoft
  intends to remove most aspects of Trace at some point after SQL Server 2016.

      This version of the requirement deals with Trace-based audit trails.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000090-DB-000065'
  tag "gid": 'V-67765'
  tag "rid": 'SV-82255r1_rule'
  tag "stig_id": 'SQL4-00-011300'
  tag "fix_id": 'F-73879r1_fix'
  tag "cci": ['CCI-000171']
  tag "nist": ['AU-12 b', 'Rev_4']
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
  tag "check": "If SQL Server Trace is not in use for audit purposes, this is
  not a finding.

  Obtain the list of approved audit maintainers from the system documentation.

  Review the server roles and individual logins that have the following
  permissions, all of which enable the ability to create and maintain audit
  definitions (the views and functions provided in the supplemental fine
  Permissions.sql can assist in this):
  ALTER TRACE
  CREATE TRACE EVENT NOTIFICATION

  The functions and views provided in the supplemental file Permissions.sql can
  assist in this review.  In the following, \"STIG\" stands for the schema where
  you have deployed these views and functions.  To see which logins and server
  roles have been granted these permissions:
      SELECT
          *
      FROM
          STIG.server_permissions P
      WHERE
          P.[Permission] IN
          (
          'ALTER TRACE',
          'CREATE TRACE EVENT NOTIFICATION'
          );

  To see what logins and server roles inherit these permissions from the server
  roles reported by the previous query, repeat the following for each one:
      SELECT * FROM STIG.members_of_server_role(<server role name>);

  To see all the permissions in effect for a server principal (server role or
  login):
      SELECT * FROM STIG.server_effective_permissions(<principal name>);

  If designated personnel are not able to configure auditable events, this is a
  finding.

  If unapproved personnel are able to configure auditable events, this is a
  finding."
  tag "fix": "Create a server role specifically for audit maintainers, and give
  it permission to maintain traces, without granting it unnecessary permissions:
    USE master;
    GO
    CREATE SERVER ROLE SERVER_AUDIT_MAINTAINERS;
    GO
    GRANT ALTER TRACE TO SERVER_AUDIT_MAINTAINERS;
    -- Next line only if required:
    GRANT CREATE TRACE EVENT NOTIFICATION TO SERVER_AUDIT_MAINTAINERS;
    GO
  (The role name used here is an example; other names may be used.)

  Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements
  to remove the ALTER TRACE and CREATE TRACE EVENT NOTIFICATION permissions from
  all logins.

  Then, for each authorized login, run the statement:
  ALTER SERVER ROLE SERVER_AUDIT_MAINTAINERS ADD MEMBER <login name>;
  GO"

  sql = mssql_session(user: attribute('user'),
                      password: attribute('password'),
                      host: attribute('host'),
                      instance: attribute('instance'),
                      port: attribute('port'))
  permissions_audit = sql.query("SELECT Grantee as result FROM STIG.server_permissions P WHERE
         P.[Permission] IN
         (
         'ALTER TRACE',
         'CREATE TRACE EVENT NOTIFICATION'
         );").column('result')
  
  if input('server_trace_implemented') != "true"
    impact 0.0
    describe 'Server Trace is not implemented, this is not a finding' do
      skip 'Server Trace is not implemented, this is not a finding'
    end
  else if  permissions_audit.empty?
    impact 0.0
    describe 'There are no sql approved audit maintainers, control N/A' do
      skip 'There are no sql approved audit maintainers, control N/A'
    end
  else
    permissions_audit.each do |grantee|
      describe "sql audit maintainers: #{grantee}" do
        subject { grantee }
        it { should be_in input('approved_audit_maintainers') }
      end
    end
  end
end
