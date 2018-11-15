control 'V-67941' do
  title "SQL Server must off-load audit data to a separate log management
  facility; this must be continuous and in near real time for systems with a
  network connection to the storage facility and weekly or more often for
  stand-alone systems."
  desc "Information stored in one location is vulnerable to accidental or
  incidental deletion or alteration.

      Off-loading is a common process in information systems with limited audit
  storage capacity.

      The DBMS may write audit records to database tables, to files in the file
  system, to other kinds of local repository, or directly to a centralized log
  management system. Whatever the method used, it must be compatible with
  off-loading the records to the centralized system.

      This applies to all data output for audit trail purposes, whether produced
  by SQL Server Audit, Trace, or other means; but excluding audit-trail
  information built into application data.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000515-DB-000318'
  tag "gid": 'V-67941'
  tag "rid": 'SV-82431r1_rule'
  tag "stig_id": 'SQL4-00-038700'
  tag "fix_id": 'F-74057r1_fix'
  tag "cci": ['CCI-001851']
  tag "nist": ['AU-4 (1)', 'Rev_4']
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
  tag "check": "Review the system documentation for a description of how audit
  records are off-loaded.

  If the database server has a continuous network connection to the centralized
  log management system, but the SQL Server audit records are not written
  directly to the centralized log management system or transferred in
  near-real-time, this is a finding.

  If the database server  does not have a continuous network connection to the
  centralized log management system, and the SQL Server audit records are not
  transferred to the centralized log management system weekly or more often, this
  is a finding."
  tag "fix": "Deploy and configure software tools to transfer audit records to
  a centralized log management system, continuously and in near-real time where a
  continuous network connection to the log management system exists, or at least
  weekly in the absence of such a connection."
  describe "SQL Server must off-load audit data to a separate log management
  facility; this must be continuous and in near real time for systems with a
  network connection to the storage facility and weekly or more often for
  stand-alone systems." do
    skip 'This control is manual'
  end
end
