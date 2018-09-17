control "V-67915" do
  title "Software updates to SQL Server must be tested before being applied to
production systems."
  desc  "While it is important to apply SQL Server updates in a timely manner,
it is also incumbent upon the database administrator and/or system
administrator to ensure that their deployment will not interfere with the
operation of the database and its applications.  Other than in emergency
situations, SQL Server updates must be applied to appropriately configured
non-production systems, and the resulting version of SQL Server assessed for
correct operation."
  impact 0.7
  tag "gtitle": "SRG-APP-000456-DB-000390"
  tag "gid": "V-67915"
  tag "rid": "SV-82405r1_rule"
  tag "stig_id": "SQL4-00-035500"
  tag "fix_id": "F-74031r1_fix"
  tag "cci": ["CCI-002605"]
  tag "nist": ["SI-2 c", "Rev_4"]
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
  tag "check": "Obtain evidence that SQL Server software updates are tested
before being applied to production servers, and that any exceptions are
approved by the ISSM.

If such evidence cannot be obtained, or the evidence that is obtained indicates
a pattern of noncompliance, this is a finding."
  tag "fix": "Institute and adhere to policies and procedures to ensure that
SQL Server updates are tested prior to installation on production servers."
end

