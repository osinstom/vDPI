from dppclient.client import Client

client = Client('10.254.184.104')


print "Creating P4 module with program: tester.p4"
status, data = client.modules.create(project_id='b63b40c0afc94cb68d3db8bc13c4c189',
                               network_id='af707ff8-d0f4-470b-8743-83e5c615ce12',
                               name="PROGRAM1",
                               description="Test",
                               program="tester.p4")
print status
print data


if status == 201:

    id = data['module']['id']
    print "Attaching P4 module.."
    resp = client.modules.attach(id=id,
                                 chain_with="11.0.0.19",
                                 protocol="icmp",
                                 dst_ip="11.0.0.13/32",
                                 src_ip="11.0.0.7/32")
    print resp.status_code

    print "Configuring P4 module.."
    status = client.modules.configure(id=id,
                                      table_name='tester',
                                      match_keys=["1"],
                                      action_name='push_slowpath',
                                      action_data=[],
                                      priority=1)
    print resp.status_code
