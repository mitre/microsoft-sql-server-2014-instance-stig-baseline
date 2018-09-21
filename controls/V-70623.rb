control "V-70623" do
  title "The SQL Server Browser service must be disabled if its use is not
  necessary.."
  desc  "The SQL Server Browser simplifies the administration of SQL Server,
  particularly when multiple instances of SQL Server coexist on the same
  computer.  It avoids the need to hard-assign port numbers to the instances and
  to set and maintain those port numbers in client systems.  It enables
  administrators and authorized users to discover database management system
  instances, and the databases they support, over the network.

      This convenience also presents the possibility of unauthorized individuals
  gaining knowledge of the available SQL Server resources.  Therefore, it is
  necessary to consider whether the SQL Server Browser is needed.  Typically, if
  only a single instance is installed, using the default name (MSSQLSERVER) and
  port assignment (1433), the Browser is not adding any value.   The more complex
  the installation, the more likely SQL Server Browser is to be helpful.

      This requirement is not intended to prohibit use of the Browser service in
  any circumstances; rather, it calls for administrators and management to
  consider whether the benefits of its use outweigh the potential negative
  consequences.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000516-DB-999900"
  tag "gid": "V-70623"
  tag "rid": "SV-85245r1_rule"
  tag "stig_id": "SQL4-00-039100"
  tag "fix_id": "F-77157r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "If the need for the SQL Server Browser service is documented,
  with appropriate approval, this is not a finding.

  Open the Services tool.

  Either navigate, via the Windows Start Menu and/or Control Panel, to
  \"Administrative Tools\", and select \"Services\"; or at a command prompt, type
  \"services.msc\" and press the \"Enter\" key.

  Scroll to \"SQL Server Browser\".

  If its Startup Type is not shown as \"Disabled\", this is a finding."
  tag "fix": "If SQL Server Browser is needed, document the justification and
  obtain the appropriate approvals.

  Where SQL Server Browser is judged unnecessary, in the Services tool,
  double-click on \"SQL Server Browser\" to open its \"Properties\" dialog.

  Set Startup Type to \"Disabled\".

  If Service Status is \"Running\", click on \"Stop\".

  Click on \"OK\"."
  describe command("Invoke-Sqlcmd -Query 'SELECT * FROM master.sys.server_triggers' -ServerInstance 'WIN-FC4ANINFUFP'") do
   its('stdout') { should eq '' }
  end
end

