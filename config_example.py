#rename file to "config.py"

# Generate key and iv with:
# $ openssl enc -aes-128-cbc -k secret -P -md sha1 -pbkdf2 -iter 1000
# for added security, use the generated "salt" as upload_endpoint
key = "DFC170B2F484BB16CEA0EE8FFF53E21F"  # Convert hex to bytes
iv = "7F2C02DE7B7EF2E879A12798232C21A6"    # Convert hex to bytes

server_ip = "127.0.0.1"
upload_port = 4097
upload_endpoint = "C5FE7B99B79A8D98"

