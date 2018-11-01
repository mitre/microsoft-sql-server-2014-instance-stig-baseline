control "V-67831" do
  title "SQL Server must have the SQL Server Distributed Replay Client software
  component removed if it is unused."
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by default
  or selected for installation by an administrator, may not be necessary to
  support essential organizational operations (e.g., key missions, functions).

      Applications must adhere to the principles of least functionality by
  providing only essential capabilities.  Unused and unnecessary SQL Server
  components increase the number of available attack vectors.  By minimizing the
  services and applications installed on the system, the number of potential
  vulnerabilities is reduced.

      The SQL Server Distributed Replay Client software component must be removed
  if it is unused.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-67831"
  tag "rid": "SV-82321r1_rule"
  tag "stig_id": "SQL4-00-016805"
  tag "fix_id": "F-73947r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "If the SQL Server service \"SQL Server Distributed Replay
  Client\" is used and satisfies organizational requirements, this is not a
  finding.

  From a command prompt or the Start menu, using an account with System
  Administrator Privilege, open services.msc.  Look for: \"SQL Server Distributed
  Replay Client\".

  If the \"SQL Server Distributed Replay Client\" service exists, this is a
  finding."
  tag "fix": "Either using the Start menu or via the command \"control.exe\",
  open the Windows Control Panel.  Open Programs and Features.  Double-click on
  Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.
  Wait for the Remove wizard to appear.

  Select a SQL Server instance; click Next.  (Note: all instances of SQL Server
  2012 or higher may be affected by this action.)

  Select Distributed Replay Client; click Next.

  Follow the remaining prompts, to remove Distributed Replay Client from SQL
  Server."

  sql_server_distributed_replay_client_used = attribute('sql_server_distributed_replay_client_used')
  is_sql_server_distributed_replay_client_installed = command("Get-Service | Findstr /c:'Distributed Replay Client'").stdout.strip
  describe.one do
    describe 'SQL Server Distributed Replay Client is in use' do
      subject { sql_server_distributed_replay_client_used }
      it { should be true }
    end
    describe 'Is SQL Server Distributed Replay Client installed' do
      subject { is_sql_server_distributed_replay_client_installed }
      it { should eq '' }
    end
  end
end

