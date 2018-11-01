control "V-67785" do
  title "Unless it has been determined that availability is paramount, SQL
  Server must shut down upon the failure of an Audit, or a Trace used for
  auditing purposes, to include the unavailability of space for more audit/trace
  log records."
  desc  "It is critical that when SQL Server is at risk of failing to process
  audit logs as required, it take action to mitigate the failure. Audit
  processing failures include: software/hardware errors; failures in the audit
  capturing mechanisms; and audit storage capacity being reached or exceeded.
  Responses to audit failure depend upon the nature of the failure mode.

      When the need for system availability does not outweigh the need for a
  complete audit trail, SQL Server should shut down immediately, rolling back all
  in-flight transactions.

      Systems where audit trail completeness is paramount will most likely be at
  a lower MAC level than MAC I; the final determination is the prerogative of the
  application owner, subject to Authorizing Official concurrence. In any case,
  sufficient auditing resources must be allocated to avoid a shutdown in all but
  the most extreme situations.

      Use of SQL Server Audit is recommended.  All features of SQL Server Audit
  are available in the Enterprise and Developer editions of SQL Server 2014.  It
  is not available at the database level in other editions.  For this or legacy
  reasons, the instance may be using SQL Server Trace for auditing, which remains
  an acceptable solution for the time being.  Note, however, that Microsoft
  intends to remove most aspects of Trace at some point after SQL Server 2016.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000109-DB-000049"
  tag "gid": "V-67785"
  tag "rid": "SV-82275r1_rule"
  tag "stig_id": "SQL4-00-013000"
  tag "fix_id": "F-73901r2_fix"
  tag "cci": ["CCI-000140"]
  tag "nist": ["AU-5 b", "Rev_4"]
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

  If the system documentation indicates that availability takes precedence over
  audit trail completeness, this is not applicable (NA).

  If SQL Server Trace is in use for audit purposes, run the statement:
  SELECT * FROM sys.traces;

  In the results of the SELECT, identify the row representing the trace used for
  audit purposes.  Examine the values in that row.

  If is_shutdown = 0, this is a finding.

  If SQL Server Audit is in use, review the defined server audits by running the
  statement:
  SELECT * FROM sys.server_audits;
  By observing the [name] and [is_state_enabled] columns, identify the row or
  rows in use.

  If the [on_failure_desc] is \"SHUTDOWN SERVER INSTANCE\" on this/these row(s),
  this is not a finding.  Otherwise, this is a finding."
  tag "fix": "If Trace is in use for audit purposes, redefine the trace, with
  @options = 6.  The script provided in the supplemental file Trace.sql can be
  used to do this.

  If SQL Server Audit is in use, configure SQL Server Audit to shut SQL Server
  down upon audit failure, to include running out of space for audit logs.  Run
  this T-SQL script for each identified audit:
  ALTER SERVER AUDIT <server_audit_name> WITH (STATE = OFF);
  GO
  ALTER SERVER AUDIT <server_audit_name> WITH (ON_FAILURE = SHUTDOWN);
  GO
  ALTER SERVER AUDIT <server_audit_name> WITH (STATE = ON);
  GO
  The audit defined in the supplemental file Audit.sql includes this setting."

  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              )


  server_trace_implemented = attribute('server_trace_implemented')
  server_audit_implemented = attribute('server_audit_implemented')

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

  query_trace_shutdown = %(
  SELECT * FROM sys.traces WHERE is_shutdown = 0;

  )

  query_audit_shutdown = %(
  SELECT * FROM sys.server_audits WHERE on_failure_desc != 'SHUTDOWN SERVER INSTANCE';

  )

  query_traces = %(
    SELECT * FROM sys.traces
  )
   if server_trace_implemented
      describe 'List defined traces for the SQL server instance with shutdown disabled' do
         subject { sql_session.query(query_trace_shutdown).column('id')}
        it { should be_empty }
      end

  end

  if server_audit_implemented
      describe 'List defined audits for the SQL server instance with shutdown disabled' do
         subject { sql_session.query(query_audit_shutdown).column('on_failure_desc')}
        it { should be_empty }
      end

  end

end

