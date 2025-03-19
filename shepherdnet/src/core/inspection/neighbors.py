from netmiko import ConnectHandler

def get_ip_neighbor_info(device_type, host, username, password):

    with ConnectHandler(device_type=device_type, host=host, username=username, password=password) as conn:
        command = "show ip neigh"
        output = conn.send_command(command)
        return output