control 'V-67891' do
  title "SQL Server must allocate audit record storage capacity in accordance
  with organization-defined audit record storage requirements."
  desc "In order to ensure sufficient storage capacity for the audit logs, SQL
  Server must be able to allocate audit record storage capacity. Although another
  requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded
  to a centralized log management system, it remains necessary to provide space
  on the database server to serve as a buffer against outages and capacity limits
  of the off-loading mechanism.

      In determining the capacity requirements, consider such factors as: total
  number of users; expected number of concurrent users during busy periods;
  number and type of events being monitored; types and amounts of data being
  captured; the frequency/speed with which audit records are off-loaded to the
  central log management system; and any limitations that exist on the ability to
  reuse the space formerly occupied by off-loaded records.

      As noted elsewhere in this document, SQL Server's Audit and/or Trace
  features can be used for auditing purposes.  This requirement applies to both.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000357-DB-000316'
  tag "gid": 'V-67891'
  tag "rid": 'SV-82381r1_rule'
  tag "stig_id": 'SQL4-00-033000'
  tag "fix_id": 'F-74007r1_fix'
  tag "cci": ['CCI-001849']
  tag "nist": ['AU-4', 'Rev_4']
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
  tag "check": "Investigate whether there have been any incidents where the
  system ran out of audit log space (to include traces used for audit purposes)
  since the last time the space was allocated or other corrective measures were
  taken.

  If there have been, this is a finding."
  tag "fix": 'Allocate sufficient audit storage space to support peak demand.'
  describe "SQL Server must allocate audit record storage capacity in accordance
  with organization-defined audit record storage requirements." do
    skip 'This control is manual'
  end
end
