from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
bruh = 0
# List of root DNS servers
ROOT_SERVERS = [
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "199.9.14.201"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33")
]
cache = {}
DNS_PORT = 53

def get_dns_record(udp_socket, domain: str, parent_server_ip: str, record_type):
    global bruh
    #print(f"Query {bruh}: {domain} from {parent_server_ip}")
    bruh += 1
    """Sends a DNS query and parses the response"""
    q = DNSRecord.question(domain, qtype=record_type)
    q.header.rd = 0  # Recursion Desired? NO
    #print("DNS query", repr(q))
    udp_socket.sendto(q.pack(), (parent_server_ip, DNS_PORT))
    pkt, _ = udp_socket.recvfrom(8192)
    buff = DNSBuffer(pkt)

    header = DNSHeader.parse(buff)

    if q.header.id != header.id:
        print("Unmatched transaction")
        return None, None, None
    if header.rcode != RCODE.NOERROR:
        return None, None, None
    
    questions = [DNSQuestion.parse(buff) for _ in range(header.q)]
    answers = [RR.parse(buff) for _ in range(header.a)]
    authorities = [RR.parse(buff) for _ in range(header.auth)]
    additionals = [RR.parse(buff) for _ in range(header.ar)]

    return answers, authorities, additionals

def resolve_domain(domain: str, sock):
    global cache
    """Iteratively resolves a domain name using while loops"""
    current_servers = ROOT_SERVERS[:]  # Start with all 13 root servers
    query_source = "Root Server"  # Initial query source
    while current_servers:

        # If cached, return the result immediately
        if domain in cache:
            print(f"Cache Hit: {domain} -> {cache[domain]}")
            return domain, cache[domain]
        
        parent_server, parent_server_ip = current_servers.pop(0)  # Get a server to query
        print(f"\n######## Querying ({query_source}) {parent_server} for {domain} ########")

        # Send a DNS query to the selected server
        answers, authorities, additionals = get_dns_record(sock, domain, parent_server_ip, "A")

        # If we got no records, continue with the next server
        if answers is None and authorities is None and additionals is None:
            continue
        print(f"ans: {len(answers)}, auth: {len(authorities)}, add: {len(additionals)}")

        # If we got an answer, return it
        for ans in answers:
            if ans.rtype == QTYPE.A:
                ip_address = str(ans.rdata)
                cache[domain] = ip_address  # Cache the resolved IP
                print(f"({query_source}) {parent_server}  returned answer: {ip_address}")
                return domain, ip_address
            elif ans.rtype == QTYPE.CNAME:
                alias = str(ans.rdata)
                resolution = resolve_domain(alias, sock) #resolve the alias
                cache[domain] = resolution[1]  # Cache the resolved IP for the original domain
                print(f"Alias found: {domain} -> {alias} (via {parent_server})")
                return resolution

        # If we got authority records, we need to query them for the next step
        new_servers = []
        # Extract NS domain names
        ns_names = [str(auth.rdata) for auth in authorities if auth.rtype == QTYPE.NS]
        for ns_name in ns_names:
            if additionals:
                for add in additionals:
                    if str(add.rname) == ns_name and add.rtype == QTYPE.A:
                        new_servers.append((str(add.rname), str(add.rdata)))  # Add NS (name,IP) to query next
            else:
                _, ns_ip = resolve_domain(ns_name, sock)
                if ns_ip:
                    new_servers.append((ns_name, ns_ip))
                    

        # If no new servers were found, attempt to query the next server in the list
        if new_servers:
            print(f"({query_source}) {parent_server} - {parent_server_ip}  returned additional records:")
            for ns in new_servers:
                print(f"\n\t{ns[0]} -> {ns[1]}")
            # Update the list of servers to query
            current_servers = new_servers
            query_source = "TLD-NS" if "Root" in query_source else "Authoritative-NS"
        else:
            continue # No additional records found, continue with the next parent server

    return None,None  # Failed to resolve

if __name__ == '__main__':
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(2)
    while True:
        domain_name = input("Enter a domain name or .exit > ")

        if domain_name == '.exit':
            print("Exiting...")
            break
        elif domain_name == ".clear":
            cache.clear()
            print("Cache cleared")
            continue
        elif domain_name == ".list":
            print("Cached domains:")
            x=0
            for domain, ip in cache.items():
                x+=1
                print(f"[{x}] {domain} -> {ip}")
            if x==1:
                print("No cached domains")
            print()
            continue
        elif domain_name.startswith(".remove"):
            try:
                n = int(domain_name.split(" ")[1])
                if n <= 0 or n > len(cache):
                    print("Invalid cache index. Please provide a valid number.")
                    continue
                domain_to_remove = list(cache.keys())[n - 1]
                del cache[domain_to_remove]
                print(f"Removed cache entry: {domain_to_remove}")
            except ValueError:
                print("Invalid input. Please provide a valid number.")

        # try:
        #     _, ip_address = resolve_domain(domain_name, sock)

        #     if ip_address:
        #         print(f"\n###############\nResolved {domain_name} -> {ip_address}")
        #     raise Exception()
        # except Exception as e:
        #     print(f"Could not resolve {domain_name}\nError: {e}")
        _, ip_address = resolve_domain(domain_name, sock)

        if ip_address:
            print(f"\n########################\nResolved {domain_name} -> {ip_address}\n")
        else:
            print(f"Could not resolve {domain_name}")
    sock.close()