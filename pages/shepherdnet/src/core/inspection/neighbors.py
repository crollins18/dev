from netmiko import ConnectHandler

def get_bgp_neighbor_info(device_type, host, username, password):

    with ConnectHandler(device_type=device_type, host=host, username=username, password=password) as conn:
        command = "show bgp summary"
        output = conn.send_command(command)
        return output