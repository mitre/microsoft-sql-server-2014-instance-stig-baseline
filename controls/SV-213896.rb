control 'SV-213896' do
  title 'Applications must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information, such as passwords and PINs, during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password or PIN, is an example of obscuring feedback of authentication information.

Database applications may allow for entry of the account name and password as a visible parameter of the application execution command. This practice must be prohibited and disabled to prevent shoulder surfing.

This calls for review of applications, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Determine whether any applications that access the database allow for entry of the account name and password, or PIN.

If any do, determine whether these applications obfuscate authentication data; if they do not, this is a finding.'
  desc 'fix', 'Configure or modify applications to prohibit display of passwords in clear text.'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15115r313039_chk'
  tag severity: 'high'
  tag gid: 'V-213896'
  tag rid: 'SV-213896r961047_rule'
  tag stig_id: 'SQL4-00-039010'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-15113r313040_fix'
  tag 'documentable'
  tag legacy: ['SV-82357', 'V-67867']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']

  describe "Applications must obscure feedback of authentication information
  during the authentication process to protect the information from possible
  exploitation/use by unauthorized individuals." do
    skip 'This control is manual'
  end
end
