control "V-67823" do
  title "SQL Server must have the SQL Server Data Tools (SSDT) software
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

      The SQL Server Data Tools (SSDT) software component must be removed from
  SQL Server if it is unused.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-67823"
  tag "rid": "SV-82313r1_rule"
  tag "stig_id": "SQL4-00-016500"
  tag "fix_id": "F-73939r1_fix"
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
  tag "check": "Review the list of components and features installed with the
  database. Using an account with System Administrator privileges, from Command
  Prompt, open control.exe.

  Navigate to Programs and Features. Check for the following entries in the
  'Uninstall or change a program' window.

  Microsoft SQL Server Data Tools - Database Projects - Web installer entry point
  Prerequisites for SSDT

  If SQL Server Data Tools is not documented as a server requirement, and these
  entries exist, this is a finding."
  tag "fix": "Document the requirement for SQL Server Data Tools to reside on
  this server.

  If it is not required, using an account with System Administrator privileges,
  from Command Prompt, open control.exe.

  Navigate to Programs and Features. Remove the following entries in the
  'Uninstall or change a program' window.

  Microsoft SQL Server Data Tools - Database Projects - Web installer entry point
  Prerequisites for SSDT"
  describe command("Get-WmiObject -Class Win32_Product | Findstr /c:'Microsoft SQL Server Data Tools' | Findstr /v 'Caption'") do
    its('stdout') { should eq '' }
  end
end

