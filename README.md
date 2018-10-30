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
| Control | 1. Auto/Manual | 2. Describe |  3. in-progress | 4. Review-RDY  | 5. Reviewed  |  6. Tested   |  7. Automated Unit Tests |
|--------|----------|----------|----------|----------|----------|----------|------------|
|`V-67845`|   auto   |yes|yes| | | | |
|V-67905|   auto   |yes|yes| | | | |
|V-67931|   auto   |yes|yes| | | | |
|V-67871|   auto   |yes|yes| | | | |
|V-67781|   auto   |yes|yes| | | | |
|V-67791|   auto   |yes|yes| | | | |
|V-67861|   auto   |yes|yes| | | | |
|V-67921|   auto   |yes|yes| | | | |
|V-67915|  manual  |yes|yes| | | | |
|V-67855|   auto   |yes|yes| | | | |
|V-67935|   auto   |yes|yes| | | | |
|V-67875|  manual  |yes|yes| | | | |
|V-67785|   auto   |yes|yes| | | | |
|V-67841|   auto   |yes|yes| | | | |
|V-67901|   auto   |yes|yes| | | | |
|V-67911|  manual  |yes|yes| | | | |
|V-67851|   auto   |yes|yes| | | | |
|V-67795|   auto   |yes|yes| | | | |
|V-67925|   auto   |yes|yes| | | | |
|V-67777|   auto   |yes|yes| | | | |
|V-67825|   auto   |yes|yes| | | | |
|V-67887|  manual  |yes|yes| | | | |
|V-67811|  manual  |yes|yes| | | | |
|V-67941|  manual  |yes|yes| | | | |
|V-67897|   auto   |yes|yes| | | | |
|V-67835|   auto   |yes|yes| | | | |
|V-67767|   auto   |yes|yes| | | | |
|V-67815|   auto   |yes|yes| | | | |
|V-67821|   auto   |yes|yes| | | | |
|V-67773|   auto   |yes|yes| | | | |
|V-67883|  manual  |yes|yes| | | | |
|V-67893|  manual  |yes|yes| | | | |
|V-67763|  manual  |yes|yes| | | | |
|V-67831|   auto   |yes|yes| | | | |
|V-67945|   auto   |yes|yes| | | | |
|V-67805|   auto   |yes|yes| | | | |
|V-67757|   auto   |yes|yes| | | | |
|V-67387|  manual  |yes|yes| | | | |
|V-67759|  manual  |yes|yes| | | | |
|V-67889|  manual  |yes|yes| | | | |
|V-67779|   auto   |yes|yes| | | | |
|V-67769|   auto   |yes|yes| | | | |
|V-67899|  manual  |yes|yes| | | | |
|V-67849|   auto   |yes|yes| | | | |
|V-67909|  manual  |yes|yes| | | | |
|V-67919|   auto   |yes|yes| | | | |
|V-67859|   auto   |yes|yes| | | | |
|V-67939|   auto   |yes|yes| | | | |
|V-67879|  manual  |yes|yes| | | | |
|V-67789|   auto   |yes|yes| | | | |
|V-67799|  manual  |yes|yes| | | | |
|V-67869|   auto   |yes|yes| | | | |
|V-67929|   auto   |yes|yes| | | | |
|V-67829|   auto   |yes|yes| | | | |
|V-67839|  manual  |yes|yes| | | | |
|V-67819|   auto   |yes|yes| | | | |
|V-67809|  manual  |yes|yes| | | | |
|V-67787|   auto   |yes|yes| | | | |
|V-67937|   auto   |yes|yes| | | | |
|V-67843|   auto   |yes|yes| | | | |
|V-67903|   auto   |yes|yes| | | | |
|V-67913|  manual  |yes|yes| | | | |
|V-67853|   auto   |yes|yes| | | | |
|V-67867|  manual  |yes|yes| | | | |
|V-67927|   auto   |yes|yes| | | | |
|V-67797|   auto   |yes|yes| | | | |
|V-70623|   auto   |yes|yes| | | | |
|V-67847|   auto   |yes|yes| | | | |
|V-67907|   auto   |yes|yes| | | | |
|V-67783|  manual  |yes|yes| | | | |
|V-67933|   auto   |yes|yes| | | | |
|V-67873|  manual  |yes|yes| | | | |
|V-67863|   auto   |yes|yes| | | | |
|V-67923|   auto   |yes|yes| | | | |
|V-67793|   auto   |yes|yes| | | | |
|V-67917|   auto   |yes|yes| | | | |
|V-67857|   auto   |yes|yes| | | | |
|V-67817|   auto   |yes|yes| | | | |
|V-67881|   auto   |yes|yes| | | | |
|V-67771|   auto   |yes|yes| | | | |
|V-67823|   auto   |yes|yes| | | | |
|V-67833|   auto   |yes|yes| | | | |
|V-67761|  manual  |yes|yes| | | | |
|V-67891|   auto   |yes|yes| | | | |
|V-67807|   auto   |yes|yes| | | | |
|V-67885|  manual  |yes|yes| | | | |
|V-67827|   auto   |yes|yes| | | | |
|V-67775|   auto   |yes|yes| | | | |
|V-67813|  manual  |yes|yes| | | | |
|V-67803|   auto   |yes|yes| | | | |
|V-67765|  manual  |yes|yes| | | | |
|V-67837|   auto   |yes|yes| | | | |
|V-67895|  manual  |yes|yes| | | | |


 
Legend
- Describe: Control has been evaluated and categorized as candidate for automated tests. Describe block has been written.
- Auto/Manual: Control has been evaluated and categorized as candidate for type that needs a manual review. Describe block has been written.
- Awaiting Review: Control is ready for peer review.
- in-progress: Initial evaluation has been completed, describe statements are being worked on.
- Reviewed: Control has been peer reviewed.
- Tested: Control has been peer reviewed and improved ( if needed ) and the improvements have been peer-tested.
- Automated Unit Tested: Automation of unit testing has been developed to the final point where creation, destruction and configuration of the resources has been automated fully.

