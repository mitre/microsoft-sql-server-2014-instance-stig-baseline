control "V-67925" do
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
  tag "gtitle": "SRG-APP-000499-DB-000330"
  tag "gid": "V-67925"
  tag "rid": "SV-82415r2_rule"
  tag "stig_id": "SQL4-00-036900"
  tag "fix_id": "F-74041r1_fix"
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
  describe command("Invoke-Sqlcmd -Query \"SELECT * FROM sys.traces;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
   its('stdout') { should_not eq '' }
  end
  get_columnid = command("Invoke-Sqlcmd -Query \"SELECT id FROM sys.traces;\" -ServerInstance 'WIN-FC4ANINFUFP' | Findstr /v 'id --'").stdout.strip.split("\n")
  
  get_columnid.each do | perms|  
    a = perms.strip
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 42;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 43;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 102;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 103;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 104;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 105;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 108;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 109;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 110;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 111;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 162;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 170;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 171;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 172;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 173;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 177;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe.one do
      describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 82;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 83;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 84;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 85;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 86;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 87;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 88;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 89;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 90;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    describe command("Invoke-Sqlcmd -Query \"SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#{a}) WHERE eventid = 91;\" -ServerInstance 'WIN-FC4ANINFUFP'") do
      its('stdout') { should_not eq '' }
    end
    end
  end
  describe command("Invoke-Sqlcmd -Query \"SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id = (SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = 'spec1') AND audit_action_name IN ( 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP', 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP', 'DATABASE_OWNERSHIP_CHANGE_GROUP', 'DATABASE_PERMISSION_CHANGE_GROUP', 'DATABASE_ROLE_MEMBER_CHANGE_GROUP', 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP', 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP', 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP', 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP', 'SERVER_PERMISSION_CHANGE_GROUP', 'SERVER_ROLE_MEMBER_CHANGE_GROUP', 'SCHEMA_OBJECT_ACCESS_GROUP' ) AND audited_result != 'SUCCESS' AND audited_result != 'SUCCESS AND FAILURE';\" -ServerInstance 'WIN-FC4ANINFUFP'") do
   its('stdout') { should eq '' }
  end
end

