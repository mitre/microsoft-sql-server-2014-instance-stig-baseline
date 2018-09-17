control "V-67867" do
  title "Applications must obscure feedback of authentication information
during the authentication process to protect the information from possible
exploitation/use by unauthorized individuals."
  desc  "To prevent the compromise of authentication information, such as
passwords and PINs, during the authentication process, the feedback from the
information system must not provide any information that would allow an
unauthorized user to compromise the authentication mechanism.

    Obfuscation of user-provided information when typed into the system is a
method used in addressing this risk.

    For example, displaying asterisks when a user types in a password or PIN,
is an example of obscuring feedback of authentication information.

    Database applications may allow for entry of the account name and password
as a visible parameter of the application execution command. This practice must
be prohibited and disabled to prevent shoulder surfing.

    This calls for review of applications, which will require collaboration
with the application developers. It is recognized that in many cases, the
database administrator (DBA) is organizationally separate from the application
developers and may have limited, if any, access to source code. Nevertheless,
protections of this type are so important to the secure operation of databases
that they must not be ignored. At a minimum, the DBA must attempt to obtain
assurances from the development organization that this issue has been addressed
and must document what has been discovered.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000178-DB-000083"
  tag "gid": "V-67867"
  tag "rid": "SV-82357r2_rule"
  tag "stig_id": "SQL4-00-039010"
  tag "fix_id": "F-73983r1_fix"
  tag "cci": ["CCI-000206"]
  tag "nist": ["IA-6", "Rev_4"]
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
  tag "check": "Determine whether any applications that access the database
allow for entry of the account name and password, or PIN.

If any do, determine whether these applications obfuscate authentication data;
if they do not, this is a finding."
  tag "fix": "Configure or modify applications to prohibit display of passwords
in clear text."
end

