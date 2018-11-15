control 'V-67817' do
  title "SQL Server must have the publicly available Northwind sample database
  removed."
  desc "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

      It is detrimental for applications to provide, or install by default,
  functionality exceeding requirements or mission objectives. Examples include,
  but are not limited to, installing advertising software, demonstrations, or
  browser plug-ins not related to requirements and providing a wide array of
  functionality not required for every mission, but which cannot be disabled.

      Applications must adhere to the principles of least functionality by
  providing only essential capabilities. Even though the very popular
  \"Northwind\" database is no longer installed by default, it introduces a
  vulnerability to SQL Server and must be removed, if present.

      Demonstration and sample database objects and applications present publicly
  known attack points for malicious users. These demonstration and sample objects
  are meant to provide simple examples of coding specific functions and are not
  developed to prevent vulnerabilities from being introduced to the SQL Server
  and the OS.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000141-DB-000090'
  tag "gid": 'V-67817'
  tag "rid": 'SV-82307r1_rule'
  tag "stig_id": 'SQL4-00-016200'
  tag "fix_id": 'F-73933r1_fix'
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
  tag "check": "Check SQL Server for the existence of the publicly available
  \"Northwind\" database by performing the following query:

  SELECT name FROM sysdatabases WHERE name LIKE 'Northwind%';

  If the \"Northwind\" database is present, this is a finding."
  tag "fix": "Remove the publicly available \"Northwind\" database from SQL
  Server by running the following script:

  USE master;
  GO
  DROP DATABASE Northwind;
  GO"

  query = %(
   SELECT name FROM sysdatabases WHERE name LIKE 'Northwind%';
    )
  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'))

  describe 'Listing the Northwind database in sysdatabases' do
    subject { sql_session.query(query).column('name') }
    it { should be_empty }
  end
end
