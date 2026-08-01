import nmap

def scan_ports(target):

    scanner = nmap.PortScanner(
        nmap_search_path=("C:\\Program Files (x86)\\Nmap\\nmap.exe",)
    )

    scanner.scan(target, '1-1024')

    results = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():

            ports = scanner[host][proto].keys()

            for port in ports:

                results.append({
                    "port": port,
                    "state": scanner[host][proto][port]['state']
                })

    return results