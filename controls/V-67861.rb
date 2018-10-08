AUTHORIZED_PORTS= attribute(
  'authorized_ports',
  description: 'List of authorized network ports for the SQL server',
  default: ["TCP Port                                TcpPort                                 1433",
            "TCP Port                                TcpDynamicPorts"]                            
)
control "V-67861" do
  title "SQL Server and Windows must be configured to prohibit or restrict the
  use of unauthorized network ports."
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

      Additionally, it is sometimes convenient to provide multiple services from
  a single component of an information system (e.g., email and web services) but
  doing so increases risk over limiting the services provided by any one
  component.

      To support the requirements and principles of least functionality, the
  application must support the organizational requirements providing only
  essential capabilities and limiting the use of ports, protocols, and/or
  services to only those required, authorized, and approved to conduct official
  business or to address authorized quality of life issues.

      Database Management Systems using ports, protocols, and services deemed
  unsafe are open to attack through those ports, protocols, and services. This
  can allow unauthorized access to the database and, through the database, to
  other components of the information system.

      For information on approved and prohibited ports, protocols, and services,
  see the Ports, Protocols, and Services Management (PPSM) section of the
  Information Assurance Support Environment (IASE) web site:
  http://iase.disa.mil/ppsm/Pages/index.aspx.

      Functions in this requirement refers to system and infrastructure
  functionality, not to functions in mathematics and programming languages.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000142-DB-000094"
  tag "gid": "V-67861"
  tag "rid": "SV-82351r1_rule"
  tag "stig_id": "SQL4-00-017410"
  tag "fix_id": "F-73977r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  tag "check": "Review the ports used by SQL Server.

  If these are in conflict with PPSM guidance, and not explained and approved in
  the system documentation, this is a finding."
  tag "fix": "Change the ports used by SQL Server to comply with PPSM guidance,
  or document the need for other ports, and obtain written approval.  Close ports
  no longer needed."
  get_ports = command("Invoke-Sqlcmd -Query \"SELECT 'TCP Port' as tcpPort, value_name, value_data FROM sys.dm_server_registry WHERE registry_key LIKE '%IPALL' AND value_name in ('TcpPort','TcpDynamicPorts')\" -ServerInstance 'WIN-FC4ANINFUFP' | Findstr /v 'value_name ---'").stdout.strip.split("\r\n")
  get_ports.each do | port|  
    a = port.strip
    describe "#{a}" do
      it { should be_in AUTHORIZED_PORTS }
    end  
  end 
end

