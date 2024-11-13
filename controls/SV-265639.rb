control 'SV-265639' do
  title 'Microsoft SQL Server products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.
Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the version and release information.

Verify the SQL Server version via one of the following methods:
Connect to the server by using Object Explorer in SQL Server Management Studio. After Object Explorer is connected, it will show the version information in parentheses, together with the user name that is used to connect to the specific instance of SQL Server.

Or, from SQL Server Management Studio:

SELECT @@VERSION;

More information for finding the version is available at the following link:
https://learn.microsoft.com/en-us/troubleshoot/sql/releases/find-my-sql-version

SQL Server 2014 is no longer supported by the vendor. If the system is running SQL Server 2014 or earlier, this is a finding.'
  desc 'fix', 'Upgrade unsupported DBMS or unsupported components to a supported version of the product.'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-69555r998186_chk'
  tag severity: 'high'
  tag gid: 'V-265639'
  tag rid: 'SV-265639r998191_rule'
  tag stig_id: 'SQL4-00-039200'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-69462r998185_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']

  describe 'This test currently has no automated tests, checks must be done manually' do
    skip 'This check must be preformed manually'
  end
end
