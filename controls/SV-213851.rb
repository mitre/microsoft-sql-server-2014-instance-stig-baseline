control 'SV-213851' do
  title 'SQL Server must be configured to prohibit or restrict the use of unauthorized network ports.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Additionally, it is sometimes convenient to provide multiple services from a single component of an information system (e.g., email and web services) but doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and, through the database, to other components of the information system.

For information on approved and prohibited ports, protocols, and services, see the Ports, Protocols, and Services Management (PPSM) section of DoD Cyber Exchange web site: https://public.cyber.mil/connect/ppsm/.

"Functions" in this requirement refers to system and infrastructure functionality, not to functions in mathematics and programming languages.'
  desc 'check', 'Review the ports used by SQL Server.

If these are in conflict with PPSM guidance, and not explained and approved in the system documentation, this is a finding.'
  desc 'fix', 'Change the ports used by SQL Server to comply with PPSM guidance, or document the need for other ports, and obtain written approval.  Close ports no longer needed.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15070r312904_chk'
  tag severity: 'medium'
  tag gid: 'V-213851'
  tag rid: 'SV-213851r960966_rule'
  tag stig_id: 'SQL4-00-017410'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-15068r312905_fix'
  tag 'documentable'
  tag legacy: ['SV-82351', 'V-67861']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  query_port_name = %(
    SELECT value_name, value_data FROM sys.dm_server_registry WHERE registry_key LIKE '%IPALL' AND value_name in ('TcpPort','TcpDynamicPorts')
  )

  query_port = %(
    SELECT value_name, value_data FROM sys.dm_server_registry WHERE registry_key LIKE '%IPALL' AND value_name in ('TcpPort','TcpDynamicPorts') AND value_data != ''
  )

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'))

  port_name = sql_session.query(query_port_name).column('value_name')
  port_name.each do |name1|
    describe "port name: #{name1}" do
      subject { name1 }
      it { should be_in input('authorized_ports_name') }
    end
  end

  port = sql_session.query(query_port).column('value_data')
  port.each do |ports|
    describe "port: #{ports}" do
      subject { ports }
      it { should be_in input('authorized_ports') }
    end
  end

  if port_name.empty? && port.empty?
    describe 'ports' do
      subject { port_name }
      it { should be_empty }
    end
  end
end
