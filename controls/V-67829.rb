control 'V-67829' do
  title "SQL Server must have the SQL Server Analysis Services (SSAS) software
  component removed if it is unused."
  desc "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by default
  or selected for installation by an administrator, may not be necessary to
  support essential organizational operations (e.g., key missions, functions).

      Applications must adhere to the principles of least functionality by
  providing only essential capabilities.  Unused and unnecessary SQL Server
  components increase the number of available attack vectors.  By minimizing the
  services and applications installed on the system, the number of potential
  vulnerabilities is reduced.

      The SQL Server Analysis Service (SSAS) software component removed from SQL
  Server if it is unused.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000141-DB-000091'
  tag "gid": 'V-67829'
  tag "rid": 'SV-82319r1_rule'
  tag "stig_id": 'SQL4-00-016800'
  tag "fix_id": 'F-73945r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
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
  tag "check": "If the SQL Server service \"SQL Server Analysis Services
  (<Instance Name>)\" is used and satisfies organizational requirements, this is
  not a finding.

  From a command prompt or the Start menu, using an account with System
  Administrator Privilege, open services.msc.  Look for: \"SQL Server Analysis
  Services (<Instance Name>)\".

  If the \"SQL Server Analysis Services (<Instance Name>)\" service exists, this
  is a finding."
  tag "fix": "Either using the Start menu or via the command \"control.exe\",
  open the Windows Control Panel.  Open Programs and Features.  Double-click on
  Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.
  Wait for the Remove wizard to appear.

  Select the relevant SQL Server instance; click Next.

  Select Analysis Services; click Next.

  Follow the remaining prompts, to remove SQL Server Analysis Services from SQL
  Server."

  sql_server_analysis_services_used = attribute('sql_server_analysis_services_used')

  describe.one do
    describe 'SQL Server analysis services is in use' do
      subject { sql_server_analysis_services_used }
      it { should be true }
    end
    describe service('MSSQLServerOLAPService') do
      it { should_not be_installed }
    end
  end
end
