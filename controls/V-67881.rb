control 'V-67881' do
  title "Access to database files must be limited to relevant processes and to
  authorized, administrative users."
  desc "Applications, including DBMSs, must prevent unauthorized and
  unintended information transfer via shared system resources. Permitting only
  DBMS processes and authorized, administrative users to have access to the files
  where the database resides helps ensure that those files are not shared
  inappropriately and are not open to backdoor access and manipulation."
  impact 0.5
  tag "gtitle": 'SRG-APP-000243-DB-000374'
  tag "gid": 'V-67881'
  tag "rid": 'SV-82371r1_rule'
  tag "stig_id": 'SQL4-00-031400'
  tag "fix_id": 'F-73997r1_fix'
  tag "cci": ['CCI-001090']
  tag "nist": ['SC-4', 'Rev_4']
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
  tag "check": "Review the permissions granted to users by the operating
  system/file system on the database files, database transaction log files,
  database audit log files, and database backup files.

  If any user/role who is not an authorized system administrator with a need to
  know or database administrator with a need to know, or a system account for
  running DBMS processes, is permitted to read/view any of these files, this is a
  finding."
  tag "fix": "Configure the permissions granted by the operating system/file
  system on the database files, database transaction log files, database audit
  log files, and database backup files so that only relevant system accounts and
  authorized system administrators and database administrators with a need to
  know are permitted to read/view these files."

  describe.one do
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') } 
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
    end
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
      it { should be_allowed('read', by_user: 'NT SERVICE\\SQLSERVERAGENT') }
    end
  end

   describe.one do
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
    end
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') } 
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
      it { should be_allowed('read', by_user: 'NT SERVICE\\SQLSERVERAGENT') }
    end
  end
end
