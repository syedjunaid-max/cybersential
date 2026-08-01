import requests

def check_headers(domain):

    try:

        url = "http://" + domain
        r = requests.get(url)

        headers = r.headers

        security_headers = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-XSS-Protection"
        ]

        result = {}

        for header in security_headers:

            if header in headers:
                result[header] = "Present"
            else:
                result[header] = "Missing"

        return result

    except:
        return {"error": "Web scan failed"}