from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import logging
import os
import json
import requests
from time import sleep
# Global Variables
PORT = 8080
FILES_STORE_PATH = os.path.join(os.getcwd(), r'server files')
VT_POST_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VT_GET_URL = "https://www.virustotal.com/api/v3/files/"
API_KEY = "YOUR-API-KEY"
HTTP_STATUS_CODE = {200: "Successful.",
                    204: "Request rate limit exceeded. You are making more requests than allowed."
                         " You have exceeded one of your quotas (minute, daily or monthly).\n"
                         "Daily quotas are reset every day at 00:00 UTC.",
                    400: "Bad request. Your request was somehow incorrect."
                         " This can be caused by missing arguments or arguments with wrong values.",
                    401: "Authentication error. Your user may not be activated,"
                         " incorrect API key or you are not an authenticated user for this action.",
                    403: "Forbidden. You don't have enough privileges to make the request."
                         "You may be doing a request without providing an API key or you may be making a request "
                         "to a Private API without having the appropriate privileges.",
                    404: "File was not found on VirusTotal.",
                    409: "The resource already exists",
                    413: "Request entity too large: to scan a file on VirusTotal it must be less than 32MB",
                    424: "The request depended on another request and that request failed.",
                    429: "Request rate limit exceeded. You are making more requests than allowed."
                         " You have exceeded one of your quotas (minute, daily or monthly).\n"
                         "Daily quotas are reset every day at 00:00 UTC.",
                    503: "Transient server error. Retry might work.",
                    504: "The operation took too long to complete."}


def queryVT(f_path):
    # This Method gains a path of a file and sends a POST request of it to scan it with VirtualTotal

    # Classifying the size of the file (Larger than 32MB)
    if os.path.getsize(f_path) < 32*(10**6):
        # making POST request to send to VT
        params = {'apikey': API_KEY}
        files = {'file': (f_path, open(f_path, 'rb'))}
        scan_req = requests.post(VT_POST_URL, files=files, params=params)

        # Request Status Code:
        print("Request status code: {status_code} {status_reason}".
              format(status_code=scan_req.status_code, status_reason=HTTP_STATUS_CODE[scan_req.status_code]))

    # File Size Larger than 32MB
    else:
        return {'Content': HTTP_STATUS_CODE[413],
                'Status Code': 413}

    # If the Scan was made, get the results:
    if scan_req.status_code != 200:
        return {'Content': HTTP_STATUS_CODE[scan_req.status_code],
                'Status Code': scan_req.status_code
                }
    else:
        # Response from VT:
        scan_res = scan_req.json()
        # Closing Connection of the scan request
        scan_req.close()

        # Making a request for the scan we queued
        scan_md5 = scan_res['md5']
        headers = {'x-apikey': API_KEY}
        result_req = requests.get(VT_GET_URL + scan_md5, headers=headers)
        content = result_req.content.decode('utf-8')
        # Closing Connection with VT
        result_req.close()

        # Wait for the request to be handled on VT Server (1 min MAX)
        sleep(5)
        i = 0
        while(result_req.status_code != 200 and i < 12):
            print("Waiting for VT, Request status code: {status_code} {status_reason}".
                  format(status_code=result_req.status_code, status_reason=HTTP_STATUS_CODE[result_req.status_code]))
            result_req = requests.get(VT_GET_URL + scan_md5, headers=headers)
            content = result_req.content.decode('utf-8')
            result_req.close()
            sleep(5)
            i += 1

        # Returning the content of the VT scan and the status code of the request.
        return {'Content': json.loads(content),
                'Status Code': result_req.status_code
                }


class TrapxHandler(BaseHTTPRequestHandler):

    def _set_get_response(self):
        # Setting the GET response parameters
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def _set_post_response(self, status_code):
        # Setting the POST response parameters
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        # This method handles get requests. it always returns the thread name of the request and nothing else.
        # Setting logging settings
        logging.basicConfig(filename=os.path.join(FILES_STORE_PATH, str(self.client_address) + '.txt'),
                            format='%(asctime)s %(message)s', level=logging.DEBUG)
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        message = threading.currentThread().getName()
        self._set_get_response()
        self.wfile.write(message.encode('utf-8'))

    def do_POST(self):
        # This Method handles POST requests from clients who wish to test a file on VirusTotal
        # The Method receives a POST Request containing a file and returns the VirusTotal scan results on the file
        # Setting logging settings
        logging.basicConfig(filename=os.path.join(FILES_STORE_PATH, str(self.client_address) + '.txt'),
                            format='%(asctime)s %(message)s', level=logging.DEBUG)
        # print(threading.currentThread().getName())
        # print("self.headers:\n{sh}".format(sh=self.headers))

        # Reading the Data within the POST request:
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Saving the File sent in the POST request
        if not os.path.exists(FILES_STORE_PATH):
            os.mkdir(FILES_STORE_PATH)
        with open(os.path.join(FILES_STORE_PATH, self.headers['File-Name']), 'wb') as f:
            f.write(post_data)
            f_path = os.path.join(FILES_STORE_PATH, self.headers['File-Name'])
            f.close()
        # Logging
        logging.info("POST request From {clientaddr}\nPOST Headers:\n{reqheaders}".
                     format(clientaddr=str(self.client_address), reqheaders=str(self.headers)))

        # JSON FORM VT
        vt_res = queryVT(f_path)
        json_res = vt_res['Content']

        # Response to Client
        self._set_post_response(vt_res['Status Code'])
        self.wfile.write(json.dumps(json_res).encode('utf-8'))


def main():
    # Setting up a multi-threaded http server with trapxHandler
    server = ThreadingHTTPServer(("", PORT), TrapxHandler)
    print("serving at port", PORT)
    server.serve_forever()


if __name__ == '__main__':
    main()
