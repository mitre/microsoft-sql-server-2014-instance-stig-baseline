control 'V-67939' do
  title "SQL Server must generate Trace or Audit records when concurrent
  logons/connections by the same user from different workstations occur."
  desc "For completeness of forensic analysis, it is necessary to track who
  logs on to SQL Server.

      Concurrent connections by the same user from multiple workstations may be
  valid use of the system; or such connections may be due to improper
  circumvention of the requirement to use the CAC for authentication; or they may
  indicate unauthorized account sharing; or they may be because an account has
  been compromised.

      If the fact of multiple, concurrent logons by a given user can be reliably
  reconstructed from the log entries for other events (logons/connections;
  voluntary and involuntary disconnections), then it is not mandatory to create
  additional log entries specifically for this.

      Use of SQL Server Audit is recommended.  All features of SQL Server Audit
  are available in the Enterprise and Developer editions of SQL Server 2014.  It
  is not available at the database level in other editions.  For this or legacy
  reasons, the instance may be using SQL Server Trace for auditing, which remains
  an acceptable solution for the time being.  Note, however, that Microsoft
  intends to remove most aspects of Trace at some point after SQL Server 2016.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000506-DB-000353'
  tag "gid": 'V-67939'
  tag "rid": 'SV-82429r1_rule'
  tag "stig_id": 'SQL4-00-038000'
  tag "fix_id": 'F-74055r1_fix'
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

  If SQL Server Trace is in use for audit purposes, verify that all required
  events are being audited.  From the query prompt:
  SELECT * FROM sys.traces;
  All currently defined traces for the SQL server instance will be listed.

  If no traces are returned, this is a finding.

  Determine the trace(s) being used for the auditing requirement.
  In the following, replace # with a trace ID being used for the auditing
  requirements.
  From the query prompt:
  SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

  The following required event IDs should be among those listed; if not, this is
  a finding:

  14  -- Audit Login
  15  -- Audit Logout
  16  -- Attention
  17  -- ExistingConnection

  If SQL Server Audit is in use, verify that the SUCCESSFUL_LOGIN_GROUP and
  LOGOUT_GROUP are enabled, as described in other STIG requirements; if not, this
  is a finding."
  tag "fix": "Where SQL Server Trace is in use, define and enable a trace that
  captures all auditable events.  The script provided in the supplemental file
  Trace.sql can be used to do this.

  Where SQL Server Audit is in use, enable the SUCCESSFUL_LOGIN_GROUP and
  LOGOUT_GROUP, as described in other STIG requirements."

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

  query_audits_logout_group = %(
    SELECT audited_result FROM sys.server_audit_specification_details WHERE audit_action_name = 'LOGOUT_GROUP'
  )

  query_audits_successful_login_group = %(
    SELECT audited_result FROM sys.server_audit_specification_details WHERE audit_action_name = 'SUCCESSFUL_LOGIN_GROUP'
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
          it { should include '14' }
          it { should include '15' }
          it { should include '16' }
          it { should include '17' }
        end
      end
    end
  end

  if server_audit_implemented
    describe 'SQL Server Audit:' do
      describe 'Defined Audits with Audit name LOGOUT_GROUP' do
        subject { sql_session.query(query_audits_logout_group) }
        it { should_not be_empty }
      end
      describe 'Defined Audits with Audit name SUCCESSFUL_LOGIN_GROUP' do
        subject { sql_session.query(query_audits_successful_login_group) }
        it { should_not be_empty }
      end
    end
  end
end
