control 'V-67925' do
  title "SQL Server must generate Trace or Audit records when
  privileges/permissions are deleted."
  desc  "Changes in the permissions, privileges, and roles granted to users and
  roles must be tracked. Without an audit trail, unauthorized elevation or
  restriction of privileges could go undetected. Elevated privileges give users
  access to information and functionality that they should not have; restricted
  privileges wrongly deny access to authorized users.

      In SQL Server, deleting permissions is typically done via the REVOKE or
  DENY command; or with the ALTER SERVER ROLE . . . DROP MEMBER . . . and/or
  ALTER ROLE . . . DROP MEMBER . . . statements.  However, native SQL Server
  security functionality may be supplemented with application-specific tables and
  logic, in which case the following actions on these tables and
  procedures/triggers/functions are also relevant:
      DELETE
      EXECUTE

      Use of SQL Server Audit is recommended.  All features of SQL Server Audit
  are available in the Enterprise and Developer editions of SQL Server 2014.  It
  is not available at the database level in other editions.  For this or legacy
  reasons, the instance may be using SQL Server Trace for auditing, which remains
  an acceptable solution for the time being.  Note, however, that Microsoft
  intends to remove most aspects of Trace at some point after SQL Server 2016.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000499-DB-000330'
  tag "gid": 'V-67925'
  tag "rid": 'SV-82415r2_rule'
  tag "stig_id": 'SQL4-00-036900'
  tag "fix_id": 'F-74041r1_fix'
  tag "cci": ['CCI-000172']
  tag "nist": ['AU-12 c', 'Rev_4']
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
  tag "check": "If neither SQL Server Audit nor SQL Server Trace is in use for
  audit purposes, this is a finding.

  Obtain the list of locally-defined security tables (if any) that require
  tracking of Insert-Update-Delete operations.

  If SQL Server Trace is in use for audit purposes, review these tables for the
  existence of triggers to raise a custom event on each Insert-Update-Delete
  operation.

  If such triggers are not present, this is a finding.

  Check to see that all required events are being audited.  From the query prompt:
  SELECT * FROM sys.traces;

  All currently defined traces for the SQL server instance will be listed.

  If no traces are returned, this is a finding.

  Determine the trace(s) being used for the auditing requirement.
  In the following, replace # with a trace ID being used for the auditing
  requirements.
  From the query prompt:
  SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

  The following required event IDs should all be among those listed; if not, this
  is a finding:

  42  -- SP:Starting
  43  -- SP:Completed
  82-91  -- User-defined Event (required only where there are locally-defined
  security tables or procedures)
  102  -- Audit Database Scope GDR
  103  -- Audit Object GDR Event
  104  -- Audit AddLogin Event
  105  -- Audit Login GDR Event
  108  -- Audit Add Login to Server Role Event
  109  -- Audit Add DB User Event
  110  -- Audit Add Member to DB Role Event
  111  -- Audit Add Role Event
  162  -- User error message
  170  -- Audit Server Scope GDR Event
  171  -- Audit Server Object GDR Event
  172  -- Audit Database Object GDR Event
  173  -- Audit Server Operation Event
  177  -- Audit Server Principal Management Event


  If SQL Server Audit is in use, proceed as follows.

  The basic SQL Server Audit configuration provided in the supplemental file
  Audit.sql uses broad, server-level audit action groups for this purpose.  SQL
  Server Audit's flexibility makes other techniques possible.  If an alternative
  technique is in use and demonstrated effective, this is not a finding.

  Determine the name(s) of the server audit specification(s) in use.

  To look at audits and audit specifications, in Management Studio's object
  explorer, expand
  <server name> >> Security >> Audits
  and
  <server name> >> Security >> Server Audit Specifications.
  Also,
  <server name> >> Databases >> <database name> >> Security >> Database Audit
  Specifications.

  Alternatively, review the contents of the system views with \"audit\" in their
  names.

  Run the following code to verify that all GRANT, ALTER SERVER ROLE . . . ADD
  MEMBER . . .,  and/or  ALTER ROLE . . . ADD MEMBER . . .  actions, all INSERT
  and UPDATE actions on any locally-defined permissions tables, and all EXECUTE
  actions on any system or locally-defined permissions-related procedures and
  functions, are being audited:
  USE [master];
  GO
  SELECT * FROM sys.server_audit_specification_details WHERE
  server_specification_id =
  (SELECT server_specification_id FROM sys.server_audit_specifications WHERE
  [name] = '<server_audit_specification_name>')
  AND audit_action_name IN
  (
  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
  'DATABASE_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_PERMISSION_CHANGE_GROUP',
  'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
  'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_PERMISSION_CHANGE_GROUP',
  'SERVER_ROLE_MEMBER_CHANGE_GROUP',
  'SCHEMA_OBJECT_ACCESS_GROUP'
  );
  GO

  Examine the list produced by the query.

  If any locally-defined permissions tables, procedures, or functions exist, and
  the list does not include the audit action group SCHEMA_OBJECT_ACCESS_GROUP,
  this is a finding.

  If any of the other audit action groups specified in the WHERE clause are not
  included in the list, this is a finding.

  If the audited_result column is not \"SUCCESS\" or \"SUCCESS AND FAILURE\" on
  every row, this is a finding."
  tag "fix": "Where SQL Server Trace is in use, define and enable a trace that
  captures all auditable events.  The script provided in the supplemental file
  Trace.sql can be used to do this.

  Add blocks of code to Trace.sql for each custom event class (integers in the
  range 82-91; the same event class may be used for all such triggers) used in
  these triggers.

  Create triggers to raise a custom event on each locally-defined security table
  that requires tracking of Insert-Update-Delete operations.  The examples
  provided in the supplemental file CustomTraceEvents.sql can serve as the basis
  for these.

  Execute Trace.sql.

  Where SQL Server Audit is in use, design and deploy a SQL Server Audit that
  captures all auditable events.  The script provided in the supplemental file
  Audit.sql can be used for this.

  Alternatively, to add the necessary data capture to an existing server audit
  specification, run the script:
  USE [master];
  GO
  ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE
  = OFF);
  GO
  ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> ADD
  (SCHEMA_OBJECT_ACCESS_GROUP);
  GO
  ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE
  = ON);
  GO"

  server_trace_implemented = attribute('server_trace_implemented')
  server_audit_implemented = attribute('server_audit_implemented')

  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              db_name: attribute('db_name'))

  query_traces = %(
    SELECT * FROM sys.traces
  )
  query_trace_eventinfo = %(
    SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(%<trace_id>s);
  )

  query_audits = %(
    SELECT * FROM sys.server_audit_specification_details WHERE audit_action_name IN
  (
  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
  'DATABASE_OWNERSHIP_CHANGE_GROUP',
  'DATABASE_PERMISSION_CHANGE_GROUP',
  'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
  'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
  'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
  'SERVER_PERMISSION_CHANGE_GROUP',
  'SERVER_ROLE_MEMBER_CHANGE_GROUP',
  'SCHEMA_OBJECT_ACCESS_GROUP'
  );

  )

  describe.one do
    describe 'SQL Server Trace is in use for audit purposes' do
      subject { server_trace_implemented }
      it { should be true }
    end

    describe 'SQL Server Audit is in use for audit purposes' do
      subject { server_audit_implemented }
      it { should be true }
    end
  end

  query_traces = %(
    SELECT * FROM sys.traces
  )

  if server_trace_implemented
    describe 'List defined traces for the SQL server instance' do
      subject { sql_session.query(query_traces) }
      it { should_not be_empty }
    end

    trace_ids = sql_session.query(query_traces).column('id')
    describe.one do
      trace_ids.each do |trace_id|
        found_events = sql_session.query(format(query_trace_eventinfo, trace_id: trace_id)).column('eventid')
        describe "EventsIDs in Trace ID:#{trace_id}" do
          subject { found_events }
          it { should include '42' }
          it { should include '43' }
          it { should include '90' }
          it { should include '102' }
          it { should include '103' }
          it { should include '104' }
          it { should include '105' }
          it { should include '108' }
          it { should include '109' }
          it { should include '110' }
          it { should include '111' }
          it { should include '162' }
          it { should include '170' }
          it { should include '171' }
          it { should include '172' }
          it { should include '173' }
          it { should include '177' }
        end
      end
    end
  end

  if server_audit_implemented
    describe 'SQL Server Audit:' do
      describe 'Defined Audits with Audit Action SCHEMA_OBJECT_ACCESS_GROUP' do
        subject { sql_session.query(query_audits) }
        it { should_not be_empty }
      end
      describe 'Audited Result for Defined Audit Actions' do
        subject { sql_session.query(query_audits).column('audited_result').uniq.to_s }
        it { should match(/SUCCESS AND FAILURE|SUCCESS/) }
      end
    end
  end
end
