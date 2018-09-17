control "V-67799" do
  title "Audit tools used in conjunction with SQL Server  must be protected
from unauthorized access."
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data.

    Depending upon the log format and application, system and application log
tools may provide the only means to manipulate and manage application and
system log data. It is, therefore, imperative that access to audit tools be
controlled and protected from unauthorized access.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the access to audit tools.

    Audit tools include, but are not limited to, OS-provided audit tools,
vendor-provided audit tools, and open source audit tools needed to successfully
view and manipulate audit information system activity and records.

    If an attacker were to gain access to audit tools, he could analyze audit
logs for system weaknesses or weaknesses in the auditing itself. An attacker
could also manipulate logs to hide evidence of malicious activity.

    This focuses on external tools for log maintenance and review.  Other STIG
requirements govern SQL Server privileges to maintain trace or audit
definitions.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000121-DB-000202"
  tag "gid": "V-67799"
  tag "rid": "SV-82289r1_rule"
  tag "stig_id": "SQL4-00-013920"
  tag "fix_id": "F-73915r1_fix"
  tag "cci": ["CCI-001493"]
  tag "nist": ["AU-9", "Rev_4"]
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
  tag "check": "In Windows, review the access permissions to tools used to view
or modify audit log data (to include traces used for audit purposes).

If appropriate permissions and access controls to prevent unauthorized read
actions and executions are not applied to these tools, this is a finding."
  tag "fix": "Apply or modify Windows permissions on tools used to view or
modify audit log data (to include traces used for audit purposes), to make them
accessible by authorized personnel only."
end

