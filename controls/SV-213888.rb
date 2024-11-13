control 'SV-213888' do
  title 'SQL Server must generate Trace or Audit records when unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to SQL Server. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.

Use of SQL Server Audit is recommended. All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014. It is not available at the database level in other editions. For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being. Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', %q(If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Trace is in use for audit purposes, verify that all required events are being audited. From the query prompt:
SELECT * FROM sys.traces;
All currently defined traces for the SQL server instance will be listed.

If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event ID should be among those listed; if not, this is a finding:

20  -- Audit Login Failed

If SQL Server Audit is in use, proceed as follows.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses the server-level audit action group FAILED_LOGIN_GROUP for this purpose. SQL Server Audit's flexibility makes other techniques possible. If an alternative technique is in use and demonstrated effective, this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object explorer, expand
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also,
<server name> >> Databases >> <database name> >> Security >> Database Audit Specifications.

Alternatively, review the contents of the system views with "audit" in their names.

Run the following to verify that all logons and connections are being audited:
USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>')
AND audit_action_name = 'FAILED_LOGIN_GROUP';
GO

If no row is returned, this is a finding.

If the "FAILED_LOGIN_GROUP" is returned with the audited_result_column of "FAILURE" or "SUCCESS AND FAILURE", this is not a finding.

If "FAILED_LOGIN_GROUP" is not in the active audit, determine whether "Both failed and successful logins" is enabled.

In SQL Management Studio:
Right-click on the instance.
>> Select "Properties".
>> Select "Security" on the left side.
>> Check the setting for "Login auditing".

If "Both failed and successful logins" is not selected, this is a finding.)
  desc 'fix', 'Where SQL Server Trace is in use, define and enable a trace that captures all auditable events. The script provided in the supplemental file Trace.sql can be used to do this.

Where SQL Server Audit is in use, design and deploy a SQL Server Audit that captures all auditable events. The script provided in the supplemental file Audit.sql can be used for this.

To add the necessary data capture to an existing server audit specification, run the script:
USE [master];
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = OFF);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> ADD (FAILED_LOGIN_GROUP);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = ON);
GO

Alternatively, enable "Both failed and successful logins".
In SQL Management Studio:
Right-click on the instance.
>> Select "Properties".
>> Select "Security" on the left side.
>> Select "Both failed and successful logins".
>> Click "OK".'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15107r754856_chk'
  tag severity: 'medium'
  tag gid: 'V-213888'
  tag rid: 'SV-213888r961824_rule'
  tag stig_id: 'SQL4-00-037600'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-15105r754857_fix'
  tag 'documentable'
  tag legacy: ['SV-82421', 'V-67931']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  server_trace_implemented = input('server_trace_implemented')
  server_audit_implemented = input('server_audit_implemented')
  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  query_traces = %(
    SELECT * FROM sys.traces
  )
  query_trace_eventinfo = %(
    SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(%<trace_id>s);
  )

  query_audits = %(
    SELECT audited_result FROM sys.server_audit_specification_details WHERE audit_action_name = 'FAILED_LOGIN_GROUP'
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
          it { should include '20' }
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
        it { should match(/SUCCESS AND FAILURE|FAILURE/) }
      end
    end
  end
end
