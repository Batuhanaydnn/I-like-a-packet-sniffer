import http.client

def send_http_request():
    conn = http.client.HTTPConnection("www.example.com", 21)
    conn.request("GET", "/")  
    response = conn.getresponse()

    print("Response Status:", response.status)
    print("Response Headers:", response.getheaders())
    print("Response Body:")
    print(response.read().decode())

    conn.close()

if __name__ == '__main__':
    send_http_request()