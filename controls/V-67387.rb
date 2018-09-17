control "V-67387" do
  title "The Service Master Key must be backed up, stored offline and off-site."
  desc  "Backup and recovery of the Service Master Key may be critical to the
complete recovery of the database. Not having this key can lead to loss of data
during recovery."
  impact 0.7
  tag "gtitle": "SRG-APP-000231-DB-000154"
  tag "gid": "V-67387"
  tag "rid": "SV-81877r2_rule"
  tag "stig_id": "SQL4-00-024500"
  tag "fix_id": "F-73499r1_fix"
  tag "cci": ["CCI-001199"]
  tag "nist": ["SC-28", "Rev_4"]
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
  tag "check": "Review procedures for, and evidence of backup of, the SQL
Server Service Master Key in the System Security Plan.

If the procedures or evidence do not exist, this is a finding.

If the procedures do not indicate offline and off-site storage of the Service
Master Key, this is a finding.

If procedures do not indicate access restrictions to the Service Master Key
backup, this is a finding."
  tag "fix": "Document and implement procedures to safely back up and store the
Service Master Key. Include in the procedures methods to establish evidence of
backup and storage, and careful, restricted access and restoration of the
Service Master Key. Also, include provisions to store the key off-site.

BACKUP SERVICE MASTER KEY TO FILE = 'path_to_file'
ENCRYPTION BY PASSWORD = 'password';

As this requires a password, take care to ensure it is not exposed to
unauthorized persons or stored as plain text."
end

