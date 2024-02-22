# microsoft-sql-server-2014-instance-stig-baseline

InSpec profile to validate the secure configuration of Microsoft SQL Server 2014 *Instance, against [DISA](https://iase.disa.mil/stigs/)'s Microsoft SQL Server 2014 Instance Security Technical Implementation Guide (STIG) Version 1, Release 9.

\* In the Microsoft SQL Server domain, an `instance` is one installed, operational copy of the DBMS software. Although multiple SQL Server instances can coexist on a Windows server, it is customary in a production environment for a single instance to be deployed on a dedicated server.
  
## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# username MSSQL DB Server
user: ''

# password MSSQL DB Server'
password: ''

# hostname MSSQL DB Server'
host: ''

# instance name MSSQL DB Server'
instance: ''

# port MSSQL DB Server
port: 1433

# name of the specific DB being evaluated within the MSSQL server
db_name: ''

# Set to true If SQL Server Trace is in use for audit purposes
server_trace_implemented: true

# Set to true If SQL Server Audit is in use for audit purposes
server_audit_implemented: true

# Set to true if SQL Server Reporting Services is in use
sql_server_reporting_services_used: false

# Set to true if SQL Server data tools is required
sql_server_data_tools_required: false

# Set to true if SQL Server Integration Services is in use
sql_server_integration_services_used: false

# Set to true if SQL Server analysis Services is in use
sql_server_analysis_services_used: false

# Set to true if SQL Server Distributed Replay Client is in use
sql_server_distributed_replay_client_used: false

# Set to true if SQL Server Distributed Replay Controller is in use
sql_server_distributed_replay_controller_used: false

# Set to true if SQL Server full-text search is in use
sql_server_full_text_search_used: false

# Set to true if master data services is in use
master_data_services_used: false

# Set to true if data quality client is in use
data_quality_client_used: false

# Set to true if data quality services is in use
data_quality_services_used: false

# Set to true if data quality services is in use
data_quality_services_used: false

# Set to true if client tools sdk is in use
client_tools_sdk_used: false

# Set to true if sql server management tools is in use
sql_mgmt_tools_used: false

# instance name MSSQL DB Server
server_instance: ''

# List of users with permissions - ALTER TRACE, CREATE TRACE EVENT NOTIFICATION
approved_audit_maintainers: []

# List of users with audit permissions - ALTER ANY SERVER AUDIT, CONTROL SERVER, ALTER ANY DATABASE, CREATE ANY DATABASE
allowed_audit_permissions: []

# List of user with permissions -  ALTER ANY SERVER AUDIT, ALTER ANYDATABASE AUDIT, ALTER TRACE; or EXECUTE
allowed_sql_alter_permissions: []

# List of approved users with access to SQL Server Audits
approved_users_sql_audits: []

# List of sql server users with permissions - alter, create, control
approved_users_server: []

# List of sql database users with permissions - alter, create, control
approved_users_database: []

# List of sql components installed
sql_components: []

# List of authorized network protocols for the SQL server
authorized_protocols: []

# List of authorized network ports for the SQL server
authorized_ports: []

# List of authorized network port names for the SQL server
authorized_ports_name: []

# List of authorized users for the SQL server
authorized_sql_users: []

# List of users allowed to execute privileged functions - create, alter, delete
allowed_users_priv_functions: []

# List of allowed server permissions
allowed_server_permissions: []

# List of allowed database permissions
allowed_database_permissions: []

# List of Databases that require encryption
encrypted_databases: []

# Set to true if data at rest encryption is required
data_at_rest_encryption_required: false

# Set to true if full disk encryption is in place
full_disk_encryption_inplace: false

# List of user allowed to execute privileged functions
allowed_users: []

# Set to true xp cmdshell is required
is_xp_cmdshell_required: false

# List of accounts managed by the sql server
sql_managed_accounts: []

# Set to true if filestream is required
filestream_required: false

# Set to true if filestream transact access is required
filestream_transact_access_only_required: false
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/microsoft-sql-server-2014-instance-stig-baseline/archive/master.tar.gz -t winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/microsoft-sql-server-2014-instance-stig-baseline
inspec archive microsoft-sql-server-2014-instance-stig-baseline
inspec exec <name of generated archive> -t winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd microsoft-sql-server-2014-instance-stig-baseline
git pull
cd ..
inspec archive microsoft-sql-server-2014-instance-stig-baseline --overwrite
inspec exec <name of generated archive> -t winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Aaron Lippold
* Alicia Sturtevant - [asturtevant](https://github.com/asturtevant)

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/microsoft-sql-server-2014-instance-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
