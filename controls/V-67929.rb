control "V-67929" do
  title "SQL Server must generate Trace or Audit records when successful logons
  or connections occur."
  desc  "For completeness of forensic analysis, it is necessary to track
  who/what (a user or other principal) logs on to SQL Server.

    Use of SQL Server Audit is recommended.  All features of SQL Server Audit
  are available in the Enterprise and Developer editions of SQL Server 2014.  It
  is not available at the database level in other editions.  For this or legacy
  reasons, the instance may be using SQL Server Trace for auditing, which remains
  an acceptable solution for the time being.  Note, however, that Microsoft
  intends to remove most aspects of Trace at some point after SQL Server 2016.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000503-DB-000350"
  tag "gid": "V-67929"
  tag "rid": "SV-82419r2_rule"
  tag "stig_id": "SQL4-00-037500"
  tag "fix_id": "F-74045r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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

  The following required event IDs should all be among those listed; if not, this
  is a finding:

  14  -- Audit Login
  15  -- Audit Logout
  16  -- Attention
  17  -- ExistingConnection


  If SQL Server Audit is in use, proceed as follows.

  The basic SQL Server Audit configuration provided in the supplemental file
  Audit.sql uses the server-level audit action group SUCCESSFUL_LOGIN_GROUP for
  this purpose.  SQL Server Audit's flexibility makes other techniques possible.
  If an alternative technique is in use and demonstrated effective, this is not a
  finding.

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

  Run the following to verify that all logons and connections are being audited:
  USE [master];
  GO
  SELECT * FROM sys.server_audit_specification_details WHERE
  server_specification_id =
  (SELECT server_specification_id FROM sys.server_audit_specifications WHERE
  [name] = '<server_audit_specification_name>')
  AND audit_action_name = 'SUCCESSFUL_LOGIN_GROUP';
  GO

  If no row is returned, this is a finding.

  If the audited_result column is not \"SUCCESS\" or \"SUCCESS AND FAILURE\",
  this is a finding."
  tag "fix": "Where SQL Server Trace is in use, define and enable a trace that
  captures all auditable events.  The script provided in the supplemental file
  Trace.sql can be used to do this.

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
  (SUCCESSFUL_LOGIN_GROUP);
  GO
  ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE
  = ON);
  GO"
  get_columnid = command("Invoke-Sqlcmd -Query \"SELECT id FROM sys.traces;\" -ServerInstance 'WIN-FC4ANINFUFP' | Findstr /v 'id --'").stdout.strip.split("\n")
  
  get_columnid.each do | perms|  
    a = perms.strip
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 14;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 15;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 16;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 17;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
  end
  describe command("Invoke-Sqlcmd -Query \"SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id = (SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = 'spec1') AND audit_action_name = 'SUCCESSFUL_LOGIN_GROUP';\" -ServerInstance 'WIN-FC4ANINFUFP'") do
    its('stdout') { should_not eq '' }
  end
  describe command("Invoke-Sqlcmd -Query \"SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id = (SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = 'spec1') AND audit_action_name = 'SUCCESSFUL_LOGIN_GROUP' AND audited_result != 'SUCCESS' AND audited_result != 'SUCCESS AND FAILURE';\" -ServerInstance 'WIN-FC4ANINFUFP'") do
    its('stdout') { should eq '' }
  end
end

