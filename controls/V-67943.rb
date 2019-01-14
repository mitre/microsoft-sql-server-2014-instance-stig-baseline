control "V-67943" do
  title "If SQL Server authentication, using passwords, is employed, SQL Server
must enforce the DoD standards for password complexity."
  desc  "Windows domain/enterprise authentication and identification must be
used (SQL4-00-030300).  Native SQL Server authentication may be used only when
circumstances make it unavoidable; and must be documented and AO-approved.

    The DoD standard for authentication is DoD-approved PKI certificates.
Authentication based on User ID and Password may be used only when it is not
possible to employ a PKI certificate, and requires AO approval.

    In such cases, the DoD standards for password complexity must be
implemented.

    The requirements for password complexity are:
    a. minimum of 15 Characters, 1 of each of the following character sets:
    - Upper-case
    - Lower-case
    - Numeric
    - Special characters (e.g. ~ ! @ # $ % ^ and * ( ) _ + = - ' [ ] / ? > <)];
    b. Minimum number of characters changed from previous password:  50% of the
minimum password length (that is, 8).

    To enforce this in SQL Server, configure each DBMS-managed login to inherit
the rules from Windows.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000164-DB-000401"
  tag "gid": "V-67943"
  tag "rid": "SV-82433r1_rule"
  tag "stig_id": "SQL4-00-038900"
  tag "fix_id": "F-74059r1_fix"
  tag "cci": ["CCI-000192", "CCI-000193", "CCI-000194", "CCI-000195",
"CCI-000205", "CCI-001619"]
  tag "nist": ["IA-5 (1) (a)", "IA-5 (1) (a)", "IA-5 (1) (a)", "IA-5 (1) (b)",
"IA-5 (1) (a)", "IA-5 (1) (a)", "Rev_4"]
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
    AND is_policy_checked = 0 ;

If no account names are listed, this is not a finding.

For each account name listed, determine whether it is documented as requiring
exemption from the standard password complexity rules, if it is not, this is a
finding."
  tag "fix": "For each SQL Server Login identified in the Check as out of
compliance:
In SQL Server Management Studio Object Explorer, navigate to <SQL Server
instance name> >> Security >> Logins >> <login name>.  Right-click, select
Properties.  Select the check box Enforce Password Policy.  Click OK.

Alternatively, for each identified Login, run the statement:
ALTER LOGIN <login name> CHECK_POLICY = ON;"

  query = %(
  SELECT NAME
  FROM   sys.sql_logins
  WHERE  type_desc = 'SQL_LOGIN'
        AND is_disabled = 0
        AND is_expiration_checked = 0;
  )

  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'))

  describe 'The list of sql logins' do
    subject { sql_session.query(query).column('name') }
    it { should be_empty }
  end
end
