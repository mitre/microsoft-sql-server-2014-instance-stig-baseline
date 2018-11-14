control "V-67777" do
  title "SQL Server must produce Trace or Audit records containing sufficient
  information to establish the sources (origins) of the events."
  desc  "Information system auditing capability is critical for accurate
  forensic analysis. Audit record content which may be necessary to satisfy the
  requirement of this control includes, but is not limited to:  time stamps,
  source and destination addresses, user/process identifiers, event descriptions,
  success/fail indications, file names involved, and access control or flow
  control rules invoked.

      SQL Server is capable of a range of actions on data stored within the
  database. It is important, for accurate forensic analysis, to know exactly who
  performed what actions. This requires specific information regarding the source
  of the event an audit record is referring to. If the source of the event
  information is not recorded and stored with the audit record, the record itself
  is of very limited use.

      The source of the event can be a user account and sometimes a system
  account when timed jobs are run. Without information establishing the source of
  activity, the value of audit records from a forensics perspective is
  questionable. If Trace is enabled for auditing, SQL Server does capture the
  source of the event-specific information in all audit records.

      Use of SQL Server Audit is recommended.  All features of SQL Server Audit
  are available in the Enterprise and Developer editions of SQL Server 2014.  It
  is not available at the database level in other editions.  For this or legacy
  reasons, the instance may be using SQL Server Trace for auditing, which remains
  an acceptable solution for the time being.  Note, however, that Microsoft
  intends to remove most aspects of Trace at some point after SQL Server 2016.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000098-DB-000042"
  tag "gid": "V-67777"
  tag "rid": "SV-82267r2_rule"
  tag "stig_id": "SQL4-00-012100"
  tag "fix_id": "F-73891r1_fix"
  tag "cci": ["CCI-000133"]
  tag "nist": ["AU-3", "Rev_4"]
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

  If SQL Server Audit is in use, this is not a finding.

  If SQL Server Trace is in use for audit purposes, verify that for all events it
  captures the NT User Name, NT Domain Name, Host Name, Client Process ID,
  Application Name, Login Name, SPID, DB User Name, and Login SID (each where
  relevant).
  From the query prompt:
  SELECT * FROM sys.traces;

  All currently defined traces for the SQL server instance will be listed.

  If no traces are returned, this is a finding.

  Determine the trace(s) being used for the auditing requirement.
  In the following, replace # with a trace ID being used for the auditing
  requirements.
  From the query prompt:
  WITH
  EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo(#)),
  E AS (SELECT DISTINCT eventid FROM EC)
  SELECT
      E.eventid,
      CASE WHEN EC6.columnid IS NULL THEN 'NT User Name (6) missing' ELSE '6 OK'
  END AS field26,
      CASE WHEN EC7.columnid IS NULL THEN 'NT Domain Name (7) missing' ELSE '7
  OK' END AS field7,
      CASE WHEN EC8.columnid IS NULL THEN 'Host Name (8) missing' ELSE '8 OK' END
  AS field8,
      CASE WHEN EC9.columnid IS NULL THEN 'Client Process ID (9) missing' ELSE '9
  OK' END AS field9,
      CASE WHEN EC10.columnid IS NULL THEN 'Application Name (10) missing' ELSE
  '10 OK' END AS field10,
      CASE WHEN EC11.columnid IS NULL THEN 'Login Name (11) missing' ELSE '11 OK'
  END AS field11,
      CASE WHEN EC12.columnid IS NULL THEN 'SPID (12) missing' ELSE '12 OK' END
  AS field12,
      CASE WHEN EC40.columnid IS NULL THEN 'DB User Name (40) missing' ELSE '40
  OK' END AS field40,
      CASE WHEN EC41.columnid IS NULL THEN 'Login SID (41) missing' ELSE '41 OK'
  END AS field41
  FROM E E
      LEFT OUTER JOIN EC EC6
          ON  EC6.eventid = E.eventid
          AND EC6.columnid = 6
      LEFT OUTER JOIN EC EC7
          ON  EC7.eventid = E.eventid
          AND EC7.columnid = 7
      LEFT OUTER JOIN EC EC8
          ON  EC8.eventid = E.eventid
          AND EC8.columnid = 8
      LEFT OUTER JOIN EC EC9
          ON  EC9.eventid = E.eventid
          AND EC9.columnid = 9
      LEFT OUTER JOIN EC EC10
          ON  EC10.eventid = E.eventid
          AND EC10.columnid = 10
      LEFT OUTER JOIN EC EC11
          ON  EC11.eventid = E.eventid
          AND EC11.columnid = 11
      LEFT OUTER JOIN EC EC12
          ON  EC12.eventid = E.eventid
          AND EC12.columnid = 12
      LEFT OUTER JOIN EC EC40
          ON  EC40.eventid = E.eventid
          AND EC40.columnid = 40
      LEFT OUTER JOIN EC EC41
          ON  EC41.eventid = E.eventid
          AND EC41.columnid = 41
  WHERE
                  EC6.columnid IS NULL OR EC7.columnid IS NULL OR EC8.columnid IS
  NULL OR EC9.columnid IS NULL
                  OR EC10.columnid IS NULL OR EC11.columnid IS NULL OR
  EC12.columnid IS NULL
                  OR EC40.columnid IS NULL OR EC41.columnid IS NULL;

  If the resulting list indicates any field specifications are missing, this is a
  finding.

  If SQL Server Audit is in use, check to see that all audit records include
  enough information to establish the sources of the events; if not, this is a
  finding."
  tag "fix": "Design and deploy a SQL Server Audit or Trace that captures the
  NT User Name, NT Domain Name, Host Name, Client Process ID, Application Name,
  Login Name, SPID, DB User Name, and Login SID (each where relevant) for all
  auditable events.

  The script provided in the supplemental file Trace.sql can be used to create a
  trace.

  If SQL Server Audit is intended to be in use, design and deploy an Audit that
  captures all auditable events. The code provided in the supplemental file
  Audit.sql can be used as the basis for creating an Audit."

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

  query_trace_eventinfo = %(
  WITH EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo(%<trace_id>s)), E AS (SELECT DISTINCT eventid FROM EC) SELECT E.eventid, CASE WHEN EC6.columnid IS NULL THEN 'NT User Name (6) missing' ELSE '6 OK' END AS field26, CASE WHEN EC7.columnid IS NULL THEN 'NT Domain Name (7) missing' ELSE '7 OK' END AS field7, CASE WHEN EC8.columnid IS NULL THEN 'Host Name (8) missing' ELSE '8 OK' END AS field8, CASE WHEN EC9.columnid IS NULL THEN 'Client Process ID (9) missing' ELSE '9 OK' END AS field9, CASE WHEN EC10.columnid IS NULL THEN 'Application Name (10) missing' ELSE '10 OK' END AS field10, CASE WHEN EC11.columnid IS NULL THEN 'Login Name (11) missing' ELSE '11 OK' END AS field11, CASE WHEN EC12.columnid IS NULL THEN 'SPID (12) missing' ELSE '12 OK' END AS field12, CASE WHEN EC40.columnid IS NULL THEN 'DB User Name (40) missing' ELSE '40 OK' END AS field40, CASE WHEN EC41.columnid IS NULL THEN 'Login SID (41) missing' ELSE '41 OK' END AS field41 FROM E E LEFT OUTER JOIN EC EC6 ON  EC6.eventid = E.eventid AND EC6.columnid = 6 LEFT OUTER JOIN EC EC7 ON  EC7.eventid = E.eventid AND EC7.columnid = 7 LEFT OUTER JOIN EC EC8 ON  EC8.eventid = E.eventid AND EC8.columnid = 8 LEFT OUTER JOIN EC EC9 ON  EC9.eventid = E.eventid AND EC9.columnid = 9 LEFT OUTER JOIN EC EC10 ON  EC10.eventid = E.eventid AND EC10.columnid = 10 LEFT OUTER JOIN EC EC11 ON  EC11.eventid = E.eventid AND EC11.columnid = 11 LEFT OUTER JOIN EC EC12 ON  EC12.eventid = E.eventid AND EC12.columnid = 12 LEFT OUTER JOIN EC EC40 ON  EC40.eventid = E.eventid AND EC40.columnid = 40 LEFT OUTER JOIN EC EC41 ON  EC41.eventid = E.eventid AND EC41.columnid = 41 WHERE EC6.columnid IS NULL OR EC7.columnid IS NULL OR EC8.columnid IS NULL OR EC9.columnid IS NULL OR EC10.columnid IS NULL OR EC11.columnid IS NULL OR EC12.columnid IS NULL OR EC40.columnid IS NULL OR EC41.columnid IS NULL;

  )

  query_traces = %(
    SELECT * FROM sys.traces
  )
   if server_trace_implemented
      describe 'List defined traces for the SQL server instance' do
        subject { sql_session.query(query_traces).column('id')}
        it { should_not be_empty }
      end
  

    trace_ids = sql_session.query(query_traces).column('id')
      describe.one do
        trace_ids.each do |trace_id|
          found_events = sql_session.query(format(query_trace_eventinfo, trace_id: trace_id)).column('eventid')
          describe 'List defined traces for the SQL server instance that are missing' do
           subject { found_events}
          it { should be_empty }
        end
      end
    end
  end
end

