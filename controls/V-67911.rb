control "V-67911" do
  title "The confidentiality and integrity of information managed by SQL Server
  must be maintained during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or
  modified during reception, including, for example, during aggregation, at
  protocol transformation points, and during packing/unpacking. These
  unauthorized disclosures or modifications compromise the confidentiality or
  integrity of the information.

      This requirement applies only to those applications that are either
  distributed or can allow access to data nonlocally. Use of this requirement
  will be limited to situations where the data owner has a strict requirement for
  ensuring data integrity and confidentiality is maintained at every step of the
  data transfer and handling process.

      When receiving data, SQL Server, associated applications, and
  infrastructure must leverage protection mechanisms.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000442-DB-000379"
  tag "gid": "V-67911"
  tag "rid": "SV-82401r1_rule"
  tag "stig_id": "SQL4-00-035100"
  tag "fix_id": "F-74027r1_fix"
  tag "cci": ["CCI-002422"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
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
  tag "check": "If the data owner does not have a strict requirement for
  ensuring data integrity and confidentiality is maintained at every step of the
  data transfer and handling process, this is not a finding.

  If SQL Server, associated applications, and infrastructure do not employ
  protective measures against unauthorized disclosure and modification during
  reception, this is a finding."
  tag "fix": "Implement protective measures against unauthorized disclosure and
  modification during reception."
  describe "The confidentiality and integrity of information managed by SQL Server
  must be maintained during reception." do
    skip "This control is manual"
  end
end

