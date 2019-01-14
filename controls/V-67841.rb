control 'V-67841' do
  title "SQL Server must have the Data Quality Client software component
  removed if it is unused."
  desc "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by default
  or selected for installation by an administrator, may not be necessary to
  support essential organizational operations (e.g., key missions, functions).

      Applications must adhere to the principles of least functionality by
  providing only essential capabilities.  Unused and unnecessary SQL Server
  components increase the number of available attack vectors.  By minimizing the
  services and applications installed on the system, the number of potential
  vulnerabilities is reduced.

      The Data Quality Client software component must be removed from SQL Server
  if it is unused.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000141-DB-000091'
  tag "gid": 'V-67841'
  tag "rid": 'SV-82331r1_rule'
  tag "stig_id": 'SQL4-00-016830'
  tag "fix_id": 'F-73957r1_fix'
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
  tag "check": "If the Data Quality Client feature is used and satisfies
  organizational requirements, this is not a finding.

  In Windows Server 2008 R2 or lower, click on the Start button.  In the Start
  menu, navigate to All Programs >> Microsoft SQL Server 2014.

  If the \"Data Quality Services\" folder exists and contains the Data Quality
  Client program, this is a finding.

  In Windows Server 2012 or higher, click on the Start button.  In the Start
  menu, navigate to Apps >> Microsoft SQL Server 2014.

  If the Data Quality Client program is listed, this is a finding.

  In Windows Explorer, navigate to <drive where SQL Server is
  installed>:\\Program Files (x86)\\Microsoft SQL Server\\120\\Tools\\Binn\\DQ\\

  If this folder exists and contains the file DataQualityServices.exe, this is a
  finding."
  tag "fix": "Either using the Start menu or via the command \"control.exe\",
  open the Windows Control Panel.  Open Programs and Features.  Double-click on
  Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.
  Wait for the Remove wizard to appear.

  Select the relevant SQL Server instance; click Next.

  Select Data Quality Client; click Next.

  Follow the remaining prompts, to remove Data Quality Client from SQL Server."

  data_quality_client_used = attribute('data_quality_client_used')

  describe.one do
    describe 'Data Quality Client is in use' do
      subject { data_quality_client_used }
      it { should be true }
    end

    describe directory('C:\\Program Files (x86)\\Microsoft SQL Server\\120\\Tools\\Binn\\DQ') do
      it { should_not exist }
    end
  end
  describe.one do
    describe 'Data Quality Client' do
      subject { data_quality_client_used }
      it { should be true }
    end
    describe file('C:\\Program Files (x86)\\Microsoft SQL Server\\120\\Tools\\Binn\\DQ\\DataQualityServices.exe') do
      it { should_not exist }
    end
  end
end
