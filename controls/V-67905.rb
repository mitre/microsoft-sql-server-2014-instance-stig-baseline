AUTHORIZED_PROTOCOLS = attribute('authorized_protocols')

SERVER_INSTANCE = attribute('server_instance') 

control "V-67905" do
  title "SQL Server must disable communication protocols not required for
  operation."
  desc  "Having unnecessary protocols enabled exposes the system to avoidable
  threats.  In a typical installation, only TCP/IP will be required."
  impact 0.7
  tag "gtitle": "SRG-APP-000383-DB-000364"
  tag "gid": "V-67905"
  tag "rid": "SV-82395r1_rule"
  tag "stig_id": "SQL4-00-034200"
  tag "fix_id": "F-74021r1_fix"
  tag "cci": ["CCI-001762"]
  tag "nist": ["CM-7 (1) (b)", "Rev_4"]
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
  tag "check": "Review the system security plan to determine the communication
  protocols used by the SQL Server instance.

  Open SQL Server Configuration Manager from the Windows Start menu or by
  entering \"SQLServerManager12.msc\" in a Command Prompt window or in the Run
  dialog box.  Select SQL Server Network Configuration >> Protocols for <instance
  name>.  Review the list of protocols.

  If any that are not required are shown as enabled, this is a finding."
  tag "fix": "In SQL Server Configuration Manager, right-click on each enabled
  protocol that is not required.  Select Disabled.

  Close SQL Server Configuration Manager.  Restart SQL Server."
  get_protocols = command("Invoke-Sqlcmd -Query \"SELECT 'Named Pipes' AS [Protocol], iif(value_data = 1, 'Yes', 'No') AS isEnabled FROM sys.dm_server_registry WHERE registry_key LIKE '%np' AND value_name = 'Enabled' UNION SELECT 'Shared Memory', iif(value_data = 1, 'Yes', 'No') FROM sys.dm_server_registry WHERE registry_key LIKE '%sm' AND value_name = 'Enabled' UNION SELECT 'TCP/IP', iif(value_data = 1, 'Yes', 'No') FROM sys.dm_server_registry WHERE registry_key LIKE '%tcp' AND value_name = 'Enabled'\" -ServerInstance '#{SERVER_INSTANCE}' | Findstr /v 'Protocol ---'").stdout.strip.split("\r\n")
  get_protocols.each do | protocol|  
    a = protocol.strip
    describe "sql enabled protocols: #{a}" do
        subject {a}
        it { should be_in AUTHORIZED_PROTOCOLS }
      end
  end 
end 

 