"""
- NOTE: REPLACE 'N' Below with your section, year, and lab number
- CS2911 - 0NN
- Fall 202N
- Lab N
- Names:
  - 
  - 

An HTTP client

Introduction: (Describe the lab in your own words)




Summary: (Summarize your experience with the lab, what you learned, what you liked, what you
   disliked, and any suggestions you have for improvement)





"""

import socket
import re


def main():
    """
    Tests the client on a variety of resources
    """

    # Content-Length
    get_http_resource('http://www.httpvshttps.com/check.png', 'check.png')

    # chunked
    get_http_resource('http://www.httpvshttps.com/', 'index.html')

    # HTTPS example. (Just for fun.)
    # get_http_resource('https://www.httpvshttps.com/', 'https_index.html')

    # If you find fun examples of chunked or Content-Length pages, please share them with us!


def get_http_resource(url, file_name):
    """
    Get an HTTP resource from a server
           Parse the URL and call function to actually make the request.

    :param url: full URL of the resource to get
    :param file_name: name of file in which to store the retrieved resource

    (do not modify this function)
    """

    # Parse the URL into its component parts using a regular expression.
    if url.startswith('https://'):
        use_https = True
        protocol = 'https'
        default_port = 443
    else:
        use_https = False
        protocol = 'http'
        default_port = 80
    url_match = re.search(protocol + '://([^/:]*)(:\d*)?(/.*)', url)
    url_match_groups = url_match.groups() if url_match else []
    # print 'url_match_groups=',url_match_groups
    if len(url_match_groups) == 3:
        host_name = url_match_groups[0]
        host_port = int(url_match_groups[1][1:]) if url_match_groups[1] else default_port
        host_resource = url_match_groups[2]
        print('host name = {0}, port = {1}, resource = {2}'.format(host_name, host_port, host_resource))
        status_string = do_http_exchange(use_https, host_name.encode(), host_port, host_resource.encode(), file_name)
        print('get_http_resource: URL="{0}", status="{1}"'.format(url, status_string))
    else:
        print('get_http_resource: URL parse failed, request not sent')


def do_http_exchange(use_https, host, port, resource, file_name):
    """
    Get an HTTP resource from a server

    :param use_https: True if HTTPS should be used. False if just HTTP should be used.
           You can ignore this argument unless you choose to implement the just-for-fun part of the
           lab.
    :param bytes host: the ASCII domain name or IP address of the server machine (i.e., host) to
           connect to
    :param int port: port number to connect to on server host
    :param bytes resource: the ASCII path/name of resource to get. This is everything in the URL
           after the domain name, including the first /.
    :param file_name: string (str) containing name of file in which to store the retrieved resource
    :return: the status code
    :rtype: int
    """
    # Send Message
    try:
        tcp_socket = send_request(host, port, resource)
        # Get Response Code
        response_code = get_response_code(tcp_socket)
        # Get the response type and message length (-1 for chunked)
        response_type, length = get_response_type(tcp_socket)

        # Bring the socket receiver to the start of the body, past all the rest of the KV pairs
        get_to_body(tcp_socket)
        # Gets the body response from the socket
        if response_type == "Chunked":
            body = read_chunks(tcp_socket)
        elif response_type == "Length":
            body = read_length(tcp_socket, length)

        # Save to File
        save_to_file(file_name, body)

        tcp_socket.close()
        return response_code
    except socket.error:
        print('Resource Retrieval Failed.')

# Define additional functions here as necessary
# Don't forget docstrings and :author: tags


def save_to_file(file_name, body):
    file = open(file_name, 'w+b')
    file.write(body)
    file.close()


def send_request(host, port, resource):
    space = b'\x20'
    request_type = b'GET'
    version = b'HTTP/1.1'
    key = b'host'
    value = host
    crlf = b'\r\n'

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_socket.connect((host, port))
        message = request_type + space + resource + space + version + crlf + key + b':' + value + crlf + crlf
        tcp_socket.sendall(message)
        return tcp_socket
    except socket.error:
        print('Invalid Hostname.')
        raise socket.error

def read_chunks(socket):
    end = False
    line = ""
    while not end:

        # Get data size
        while not line.__contains__("\r\n"):
            temp_byte = socket.recv(1)
            line += temp_byte.decode("ASCII")
        end = line == "\r\n"

        if not end:
            size = int(line.split("\r\n")[0], 16)
            print(size)
            data = socket.recv(int(size))
        line = ""

    return data


def read_length(socket, length):
    return socket.recv(int(length))


def get_to_body(socket):
    end = False
    line = ""
    while not end:
        while not line.__contains__("\r\n"):
            temp_byte = socket.recv(1)
            line += temp_byte.decode("ASCII")
        end = line == "\r\n"
        line = ""


def get_response_type(socket):
    line = ""
    temp_byte = socket.recv(1)
    line += temp_byte.decode("ASCII")
    found = False
    while not found:
        while not line.__contains__("\r\n"):
            temp_byte = socket.recv(1)
            line += temp_byte.decode("ASCII")

        if line.startswith("Content-Length"):
            return "Length", line.split(' ')[1]
            found = True
        if line.startswith("Transfer-Encoding: chunked"):
            return "Chunked", -1
            found = True
        if line == "\r\n":
            return "Not Found"
        line = ""

    return "Not found"


def get_response_code(socket):
    temp_byte = socket.recv(1)
    while temp_byte != b'\x20':
        temp_byte = socket.recv(1)

    return socket.recv(3).decode("ASCII")


'''
def read_status_line(listen_socket):

    byte_holder = next_byte(listen_socket)
    version = b''
    status = b''
    desc = b''
    while byte_holder != b' ':
        version += byte_holder
        byte_holder = next_byte(listen_socket)
    byte_holder = next_byte(listen_socket)
    while byte_holder != b' ':
        status += byte_holder
        byte_holder = next_byte(listen_socket)
    byte_holder = next_byte(listen_socket)
    while not desc.__contains__(b'\r\n'):
        desc += byte_holder
        byte_holder = next_byte(listen_socket)
    desc = desc.decode('ASCII')[0:len(desc.decode('ASCII')) - 2].encode('ASCII')
    return status


def parse_chunked_response(listen_socket):

    body = b''
    size_byte = next_byte(listen_socket)
    size = b''
    while not int(size.decode('ASCII'), 16) == 0:
        while size_byte != b'\r':
            size += size_byte
            size_byte = next_byte(listen_socket)
        next_byte(listen_socket)
        for i in range(0, int(size.decode('ASCII'), 16)):
            body += next_byte(listen_socket)
    return body


def read_line(tcp_socket):
    byte_message = b''
    byte_holder = b''

    while byte_holder != b'\x0a':
        byte_message += byte_holder
        byte_holder = next_byte(tcp_socket)
    return byte_message.strip(b'\x0d\x0a')
'''


def next_byte(data_socket):
    """
    Read the next byte from the socket data_socket.
    Read the next byte from the sender, received over the network.
    If the byte has not yet arrived, this method blocks (waits)
      until the byte arrives.
    If the sender is done sending and is waiting for your response, this method blocks indefinitely.
    :param data_socket: The socket to read from. The data_socket argument should be an open tcp
                        data connection (either a client socket or a server data socket), not a tcp
                        server's listening socket.
    :return: the next byte, as a bytes object with a single byte in it
    """
    return data_socket.recv(1)


main()

