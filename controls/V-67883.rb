control 'V-67883' do
  title "SQL Server must automatically terminate a user session after
  organization-defined conditions or trigger events requiring session disconnect."
  desc "This addresses the termination of user-initiated logical sessions in
  contrast to the termination of network connections that are associated with
  communications sessions (i.e., network disconnect). A logical session (for
  local, network, and remote access) is initiated whenever a user (or process
  acting on behalf of a user) accesses an organizational information system. Such
  user sessions can be terminated (and thus terminate user access) without
  terminating network sessions.

      Session termination ends all processes associated with a user's logical
  session except those batch processes/jobs that are specifically created by the
  user (i.e., session owner) to continue after the session is terminated.

      Conditions or trigger events requiring automatic session termination can
  include, for example, organization-defined periods of user inactivity, targeted
  responses to certain types of incidents, and time-of-day restrictions on
  information system use.

      This capability is typically reserved for specific cases where the system
  owner, data owner, or organization requires additional assurance.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000295-DB-000305'
  tag "gid": 'V-67883'
  tag "rid": 'SV-82373r1_rule'
  tag "stig_id": 'SQL4-00-031700'
  tag "fix_id": 'F-73999r1_fix'
  tag "cci": ['CCI-002361']
  tag "nist": ['AC-12', 'Rev_4']
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
  tag "check": "Review system documentation to obtain the organization's
  definition of circumstances requiring automatic session termination.

  If the documentation explicitly states that such termination is not required or
  is prohibited, this is not a finding.

  If the documentation requires automatic session termination, but SQL Server and
  Windows (or third-party tools) are not configured accordingly, this is a
  finding."
  tag "fix": "Configure SQL Server, Windows and/or third-party tools to
  automatically terminate a user session after organization-defined conditions or
  trigger events requiring session termination."
  describe "SQL Server must automatically terminate a user session after
  organization-defined conditions or trigger events requiring session disconnect." do
    skip 'This control is manual'
  end
end
