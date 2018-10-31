control "V-67787" do
  title "Where availability is paramount, the SQL Server must continue
  processing (preferably overwriting existing records, oldest first), in the
  event of lack of space for more Audit/Trace log records; and must keep
  processing after any failure of an Audit/Trace."
  desc  "It is critical that when SQL Server is at risk of failing to process
  audit logs as required, it take action to mitigate the failure. Audit
  processing failures include: software/hardware errors; failures in the audit
  capturing mechanisms; and audit storage capacity being reached or exceeded.
  Responses to audit failure depend upon the nature of the failure mode.

      When availability is an overriding concern, approved actions in response to
  an audit failure are as follows:

      (i) If the failure was caused by the lack of audit record storage capacity,
  the DBMS must continue generating audit records, if possible (automatically
  restarting the audit service if necessary), preferably overwriting the oldest
  audit records in a first-in-first-out manner.

      (ii) If audit records are sent to a centralized collection server and
  communication with this server is lost or the server fails, the DBMS must queue
  audit records locally until communication is restored or until the audit
  records are retrieved manually. Upon restoration of the connection to the
  centralized collection server, action should be taken to synchronize the local
  audit data with the collection server.

      Systems where availability is paramount will most likely be MAC I; the
  final determination is the prerogative of the application owner, subject to
  Authorizing Official concurrence. In any case, sufficient auditing resources
  must be allocated to avoid audit data loss in all but the most extreme
  situations.

      Use of SQL Server Audit is recommended.  All features of SQL Server Audit
  are available in the Enterprise and Developer editions of SQL Server 2014.  It
  is not available at the database level in other editions.  For this or legacy
  reasons, the instance may be using SQL Server Trace for auditing, which remains
  an acceptable solution for the time being.  Note that Microsoft intends to
  remove most aspects of Trace at some point after SQL Server 2016.

      However, although Trace supports FIFO rollover, SQL Server Audit does not:
  its CONTINUE option stops the production of new audit records when there is an
  audit failure.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000109-DB-000321"
  tag "gid": "V-67787"
  tag "rid": "SV-82277r4_rule"
  tag "stig_id": "SQL4-00-030600"
  tag "fix_id": "F-73903r2_fix"
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
  tag "check": "If the system documentation indicates that availability does
  not take precedence over audit trail completeness, this is not applicable (NA).


  If SQL Server Audit is not in use, this is a finding.

  If SQL Server Audit is in use, review the defined server audits by running the
  statement:

  SELECT [name], [max_rollover_files] FROM sys.server_file_audits
  WHERE is_state_enabled = 1;
 
  By observing the [name] and [max_rollover_files] columns, identify the row or
  rows in use.

  If the [max_rollover_files] is greater than zero, this is not a finding.
  Otherwise, this is a finding."
  tag "fix": "If SQL Server Audit is in use, configure SQL Server Audit to
  continue to generate audit records, overwriting the oldest existing records, in
  the case of an auditing failure.

  Run this T-SQL script for each identified audit:

  ALTER SERVER AUDIT [AuditName] WITH (STATE = OFF);
  GO
  ALTER SERVER AUDIT [AuditName] to file (max_rollover_files = IntegerValue);
  GO
  ALTER SERVER AUDIT [AuditName] WITH (STATE = ON);
  GO"

  

  server_trace_implemented = attribute('server_trace_implemented')
  server_audit_implemented = attribute('server_audit_implemented')

  describe 'SQL Server Audit is in use for audit purposes' do
      subject { server_audit_implemented }
      it { should be true }
    end

sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              db_name: attribute('db_name'))




  query_audit = %(
  SELECT * FROM sys.server_file_audits WHERE is_state_enabled = 1 AND max_rollover_files <= 0;

  )
  if server_audit_implemented
    describe 'List audits enabled with max_rollover_files less than 0' do
      subject { sql_session.query(query_audit).column('name')}
      it { should be_empty }
    end

  end

end

