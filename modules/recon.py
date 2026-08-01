import whois
import socket

def get_domain_info(domain):

    try:
        w = whois.whois(domain)

        ip = socket.gethostbyname(domain)

        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "ip": ip
        }

    except:
        return {"error": "Recon failed"}