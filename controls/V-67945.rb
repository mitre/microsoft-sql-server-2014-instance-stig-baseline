
control "V-67945" do
  title "If SQL Server authentication, using passwords, is employed, SQL Server
  must enforce the DoD standards for password lifetime."
  desc  "Windows domain/enterprise authentication and identification must be
  used (SQL4-00-030300).  Native SQL Server authentication may be used only when
  circumstances make it unavoidable; and must be documented and AO-approved.

      The DoD standard for authentication is DoD-approved PKI certificates.
  Authentication based on User ID and Password may be used only when it is not
  possible to employ a PKI certificate, and requires AO approval.

      In such cases, the DoD standards for password lifetime must be implemented.


      The requirements for password lifetime are:
      a. Password lifetime limits for interactive accounts:  Minimum 24 hours,
  Maximum 60 days
      b. Password lifetime limits for non-interactive accounts:  Minimum 24
  hours, Maximum 365 days
      c. Number of password changes before an old one may be reused:  Minimum of
  5.

      To enforce this in SQL Server, configure each DBMS-managed login to inherit
  the rules from Windows.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000164-DB-000401"
  tag "gid": "V-67945"
  tag "rid": "SV-82435r2_rule"
  tag "stig_id": "SQL4-00-038910"
  tag "fix_id": "F-74061r1_fix"
  tag "cci": ["CCI-000198", "CCI-000199", "CCI-000200"]
  tag "nist": ["IA-5 (1) (d)", "IA-5 (1) (d)", "IA-5 (1) (e)", "Rev_4"]
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
  tag "check": "Run the statement:
  SELECT
      name
  FROM
      sys.sql_logins
  WHERE
      type_desc = 'SQL_LOGIN'
      AND is_disabled = 0
      AND is_expiration_checked = 0;

  If no account names are listed, this is not a finding.

  For each account name listed, determine whether it is documented as requiring
  exemption from the standard password lifetime rules, if it is not, this is a
  finding."
  tag "fix": "For each SQL Server Login identified in the Check as out of
  compliance:
  In SQL Server Management Studio Object Explorer, navigate to <SQL Server
  instance name> >> Security >> Logins >> <login name>.  Right-click, select
  Properties.  Select the check box Enforce Password Expiration.  Click OK.

  Alternatively, for each identified Login, run the statement:
  ALTER LOGIN <login name>  CHECK_EXPIRATION = ON;"

   query = %(
    SELECT name FROM sys.sql_logins WHERE type_desc = 'SQL_LOGIN' AND is_disabled = 0 AND is_expiration_checked = 0;
  )

 sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              )


  describe 'The list of sql logins' do
      subject { sql_session.query(query).column('name')}
      it { should be_empty}
  end
end

