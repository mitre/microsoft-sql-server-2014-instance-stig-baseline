# microsoft_sql_2014_server_stig_baseline

InSpec profile testing secure configuration of Microsoft SQL Server 2014.

## Description

This InSpec compliance profile is a collection of automated tests for secure configuration of MSSQL 2014 .

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

- [ruby](https://www.ruby-lang.org/en/) version 2.4  or greater
- [InSpec](http://inspec.io/) version 2.1  or greater
    - Install via ruby gem: `gem install inspec`

## Usage
InSpec makes it easy to run tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

### Run with remote profile:
You may choose to run the profile via a remote url, this has the advantage of always being up to date.
The disadvantage is you may wish to modify controls, which is only possible when downloaded.
Also, the remote profile is unintuitive for passing in attributes, which modify the default values of the profile.
``` bash
inspec exec https://github.com/aaronlippold/microsoft_sql_2014_server_stig_baseline/archive/master.tar.gz
```

Another option is to download the profile then run it, this allows you to edit specific instructions and view the profile code.
``` bash
# Clone Inspec Profile
$ git clone https://github.com/aaronlippold/microsoft_sql_2014_server_stig_baseline.git

# Run profile locally (assuming you have not changed directories since cloning)
# This will display compliance level at the prompt, and generate a JSON file 
# for export called output.json
$ inspec exec microsoft_sql_2014_server_stig_baseline --reporter cli json:output.json

# Run profile with custom settings defined in attributes.yml against the target 
# server example.com. 
$ inspec exec microsoft_sql_2014_server_stig_baseline-t ssh://user@password:example.com --attrs attributes.yml --reporter cli json:output.json

# Run profile with: custom attributes, ssh keyed into a custom target, and sudo.
$ inspec exec microsoft_sql_2014_server_stig_baseline -t ssh://user@hostname -i /path/to/key --sudo --attrs attributes.yml --reporter cli json:output.json
```


## Contributors + Kudos

- Aaron Lippold
- The MITRE InSpec Team

## License and Author

### Authors

- Author:: Aaron Lippold

### License 

* This project is licensed under the terms of the Apache license 2.0 (apache-2.0)

### Progress report

|Control| 2. Describe  |  1. Auto/Manual (a/m)  |  4. Review-RDY  |  3. in-progress  |  5. Reviewed  |  6. Tested   |  7. Automated Unit Tests |
|-------|-----------|-----------|-----------|-----------|-----------|-----------|------------|
|V-76679|           |    yes    |    yes    |           |           |           |            |
|V-67845.rb|  yes  | auto |yes| | | | |
|V-67905.rb|  yes  | auto |yes| | | | |
|V-67931.rb|  yes  | auto |yes| | | | |
|V-67871.rb|  yes  | auto |yes| | | | |
|V-67781.rb|  yes  | auto |yes| | | | |
|V-67791.rb|  yes  | auto |yes| | | | |
|V-67861.rb|  yes  | auto |yes| | | | |
|V-67921.rb|  yes  | auto |yes| | | | |
|V-67915.rb|  yes  |manual|yes| | | | |
|V-67855.rb|  yes  | auto |yes| | | | |
|V-67935.rb|  yes  | auto |yes| | | | |
|V-67875.rb|  yes  |manual|yes| | | | |
|V-67785.rb|  yes  | auto |yes| | | | |
|V-67841.rb|  yes  | auto |yes| | | | |
|V-67901.rb|  yes  | auto |yes| | | | |
|V-67911.rb|  yes  |manual|yes| | | | |
|V-67851.rb|  yes  | auto |yes| | | | |
|V-67795.rb|  yes  | auto |yes| | | | |
|V-67925.rb|  yes  | auto |yes| | | | |
|V-67777.rb|  yes  | auto |yes| | | | |
|V-67825.rb|  yes  | auto |yes| | | | |
|V-67887.rb|  yes  |manual|yes| | | | |
|V-67811.rb|  yes  |manual|yes| | | | |
|V-67941.rb|  yes  |manual|yes| | | | |
|V-67897.rb|  yes  | auto |yes| | | | |
|V-67835.rb|  yes  | auto |yes| | | | |
|V-67767.rb|  yes  | auto |yes| | | | |
|V-67815.rb|  yes  | auto |yes| | | | |
|V-67821.rb|  yes  | auto |yes| | | | |
|V-67773.rb|  yes  | auto |yes| | | | |
|V-67883.rb|  yes  |manual|yes| | | | |
|V-67893.rb|  yes  |manual|yes| | | | |
|V-67763.rb|  yes  |manual|yes| | | | |
|V-67831.rb|  yes  | auto |yes| | | | |
|V-67945.rb|  yes  | auto |yes| | | | |
|V-67805.rb|  yes  | auto |yes| | | | |
|V-67757.rb|  yes  | auto |yes| | | | |
|V-67387.rb|  yes  |manual|yes| | | | |
|V-67759.rb|  yes  |manual|yes| | | | |
|V-67889.rb|  yes  |manual|yes| | | | |
|V-67779.rb|  yes  | auto |yes| | | | |
|V-67769.rb|  yes  | auto |yes| | | | |
|V-67899.rb|  yes  |manual|yes| | | | |
|V-67849.rb|  yes  | auto |yes| | | | |
|V-67909.rb|  yes  |manual|yes| | | | |
|V-67919.rb|  yes  | auto |yes| | | | |
|V-67859.rb|  yes  | auto |yes| | | | |
|V-67939.rb|  yes  | auto |yes| | | | |
|V-67879.rb|  yes  |manual|yes| | | | |
|V-67789.rb|  yes  | auto |yes| | | | |
|V-67799.rb|  yes  |manual|yes| | | | |
|V-67869.rb|  yes  | auto |yes| | | | |
|V-67929.rb|  yes  | auto |yes| | | | |
|V-67829.rb|  yes  | auto |yes| | | | |
|V-67839.rb|  yes  |manual|yes| | | | |
|V-67819.rb|  yes  | auto |yes| | | | |
|V-67809.rb|  yes  |manual|yes| | | | |
|V-67787.rb|  yes  | auto |yes| | | | |
|V-67937.rb|  yes  | auto |yes| | | | |
|V-67843.rb|  yes  | auto |yes| | | | |
|V-67903.rb|  yes  | auto |yes| | | | |
|V-67913.rb|  yes  |manual|yes| | | | |
|V-67853.rb|  yes  | auto |yes| | | | |
|V-67867.rb|  yes  |manual|yes| | | | |
|V-67927.rb|  yes  | auto |yes| | | | |
|V-67797.rb|  yes  | auto |yes| | | | |
|V-70623.rb|  yes  | auto |yes| | | | |
|V-67847.rb|  yes  | auto |yes| | | | |
|V-67907.rb|  yes  | auto |yes| | | | |
|V-67783.rb|  yes  |manual|yes| | | | |
|V-67933.rb|  yes  | auto |yes| | | | |
|V-67873.rb|  yes  |manual|yes| | | | |
|V-67863.rb|  yes  | auto |yes| | | | |
|V-67923.rb|  yes  | auto |yes| | | | |
|V-67793.rb|  yes  | auto |yes| | | | |
|V-67917.rb|  yes  | auto |yes| | | | |
|V-67857.rb|  yes  | auto |yes| | | | |
|V-67817.rb|  yes  | auto |yes| | | | |
|V-67881.rb|  yes  | auto |yes| | | | |
|V-67771.rb|  yes  | auto |yes| | | | |
|V-67823.rb|  yes  | auto |yes| | | | |
|V-67833.rb|  yes  | auto |yes| | | | |
|V-67761.rb|  yes  |manual|yes| | | | |
|V-67891.rb|  yes  | auto |yes| | | | |
|V-67807.rb|  yes  | auto |yes| | | | |
|V-67885.rb|  yes  |manual|yes| | | | |
|V-67827.rb|  yes  | auto |yes| | | | |
|V-67775.rb|  yes  | auto |yes| | | | |
|V-67813.rb|  yes  |manual|yes| | | | |
|V-67803.rb|  yes  | auto |yes| | | | |
|V-67765.rb|  yes  |manual|yes| | | | |
|V-67837.rb|  yes  | auto |yes| | | | |
|V-67895.rb|  yes  |manual|yes| | | | |
 
Legend
- Describe: Control has been evaluated and categorized as candidate for automated tests. Describe block has been written.
- Auto/Manual: Control has been evaluated and categorized as candidate for type that needs a manual review. Describe block has been written.
- Awaiting Review: Control is ready for peer review.
- in-progress: Initial evaluation has been completed, describe statements are being worked on.
- Reviewed: Control has been peer reviewed.
- Tested: Control has been peer reviewed and improved ( if needed ) and the improvements have been peer-tested.
- Automated Unit Tested: Automation of unit testing has been developed to the final point where creation, destruction and configuration of the resources has been automated fully.

