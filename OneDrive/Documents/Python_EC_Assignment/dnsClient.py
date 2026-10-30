import argparse
import socket
import struct

        # Useful resources to solve this lab:
        # 1. https://datatracker.ietf.org/doc/html/rfc1034
        # 2. https://datatracker.ietf.org/doc/html/rfc1035
        # 3. Kurose/Ross Book!

def dns_query(type, name, server):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server, 53) # Enter Port Number

    # Create the DNS query
    ID = 0x1234
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 1
    RA = 0
    Z = 0
    RCODE = 0
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

        # The DNS header is fixed-size: 12 bytes total.
        # It consists of six 16-bit fields, stored in network byte order
        # (big-endian: most significant byte first).
        #
        # Some fields, like MessageID and QDCount, use all 16 bits directly.
        # The Flags field is also 16 bits, but it is divided into smaller pieces:
        # QR, Opcode, AA, TC, RD, RA, Z, and RCODE.
        #
        # To create the Flags field, each smaller value must be moved into its
        # correct bit position using left shifts (<<). The shifted values are then
        # combined with bitwise OR (|) to produce one final 16-bit number.
        #
        # For example, QR appears as the leftmost bit in the diagram, which means it
        # is the most significant bit of the 16-bit Flags field. In code, that is
        # position 15, so QR is placed using qr << 15.
        #
        # Be careful: you are responsible for putting each value in the correct
        # position before packing the header into bytes.
        #
        # In the diagram below, each row represents 16 bits (remember 8 bits = 1 byte).
        # The numbers across the top are bit positions within each 16-bit row.
        # The labeled boxes show the size and location of each DNS header field.

        # DNS Header Format (12 bytes / 96 bits)
        #
        # 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      MessageID                 |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode    |AA|TC|RD|RA| Reserved | RCODE  |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+------+ 
        # |                    QDCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+
        # |                    ANCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+
        # |                    NSCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+
        # |                    ARCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+


        # Message ID: 16 bits
        # QR (Query/Response): 1 bit
        # Opcode: 4 bits
        # AA (Authoritative Answer): 1 bit
        # TC (Truncated): 1 bit
        # RD (Recursion Desired): 1 bit
        # RA (Recursion Available): 1 bit
        # Z: 3 bits
        # Rcode (Response Code): 4 bits
        # QDCount (Question Count): 16 bits
        # ANCount (Answer Count): 16 bits
        # NSCount (Authority Count): 16 bits
        # ARCount (Additional Count): 16 bits
        
        # Example: The QR field is located in the second byte of the DNS header, with its most significant bit being the leftmost bit of this byte. Since each byte contains 8 bits, shifting the value of the QR field left by 15 bits moves it to the correct position in the 16-bit value that represents the combination of several fields in the DNS header.

    header = struct.pack('!HHHHHH', ID, QR << 15 | OPCODE << 11 | AA << 10 | TC << 9 | RD << 8 | RA << 7 | Z << 4 | RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Encode the QNAME
    
        # To do so we need to split the incoming string into parts
        
        # For example www.nyu.edu would become:
        # 1. www (length of 3)
        # 2. nyu (length of 3)
        # 3. edu (length of 3)
        
    qname_parts = name.split('.') # How can we easily split the string?
    qname_encoded_parts = [struct.pack('B', len(part)) + part.encode('utf-8') for part in qname_parts] # Make sure it's encoded as a sequence of the right character encoding type (lowercase)
    qname_encoded = b''.join(qname_encoded_parts) + b'\x00' #enter the closing byte value to signify the end of the domain string (two digits)

    # Encode the QTYPE and QCLASS

    if type == 'A':
        qtype = 1     # Lookup the Resource Record value
    elif type == 'AAAA':
        qtype = 28     # Lookup the Resource Record value
    else:
        raise ValueError('Invalid type')
    

    qclass = 1     # Lookup the Resource Record class being requested

    # This is the query we are asking the DNS Server
    question = qname_encoded + struct.pack('!HH', qtype, qclass)

    # Send the query to the server, remember we must always include our header alongside the question!
    message = header + question
    sent = sock.sendto(message, server_address)

    # Receive the response from the server
    data, _ = sock.recvfrom(4096) # This is the buffer size we have selected, 4096 Bytes is the maximum amount of data to be received at once.
    
        # A larger buffer size would allow more data to be received at once, while a smaller buffer size would limit the amount of data that can be received at once. 
        # It is a good idea to choose a buffer size that is large enough to accommodate the largest expected DNS response, but not so large that it wastes memory.
    
    # Parse the response header
    response_header = data[:12] # What is the size of the DNS response header in bytes? 
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', response_header) # We are unpacking the binary data of the response header into individual values representing the fields of the DNS header.
    
    # Parse the response question section (same as query)
    response_question = data[12:12+len(question)] # The data variable starts immediately after the header section, so what is it's index? Note the two '??' '??' will be the same value as we start at a specific index and then go for the entire length of the binary data received. 
    assert response_question == question

    # Parse the response answer section
    response_answer = data[12+len(question):] # We would be looking at the same index position as before (after the header)
    offset = 0
    for _ in range(ANCOUNT):
        # Parse the name
        name_parts = []
        while True:
            length = response_answer[offset]
            offset += 1
            if length == 0:
                break
            elif length & 0xc0 == 0xc0:
                # Pointer
                pointer = struct.unpack('!H', response_answer[offset-1:offset+1])[0] & 0x3fff
                offset += 1
                name_parts.append(parse_name(data, pointer)) # For those curious, parse_name() parses the rest of the domain name, and we append the result to the name_parts list.
                break
            else:
                # Label
                label = response_answer[offset:offset+length].decode('ascii')
                offset += length
                name_parts.append(label)
        name = '.'.join(name_parts)

        # Parse the type, class, TTL, and RDLENGTH
        type, cls, ttl, rdlength = struct.unpack('!HHIH', response_answer[offset:offset+10]) # What is the offset value in bytes? Remember 'H' represent 2 bytes, and 'I' represents 4 bytes, we declared '!HHIH'. 
        
        offset += 10 # Same value as just calculated

        # Parse the RDATA
        rdata = response_answer[offset:offset+rdlength]
        offset += rdlength

        if type == 1: # Lookup Type value
            # A record (IPv4 address)
            ipv4 = socket.inet_ntop(socket.AF_INET, rdata)
            print(f'{name} has IPv4 address {ipv4}')
            return ipv4
        elif type == 28: # Lookup Type value
            # AAAA record (IPv6 address)
            ipv6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(f'{name} has IPv6 address {ipv6}')
            return ipv6                

def parse_name(data, offset):
    name_parts = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        elif length & 0xc0 == 0xc0:
            # Pointer
            pointer = struct.unpack('!H', data[offset-1:offset+1])[0] & 0x3fff
            offset += 1
            name_parts.append(parse_name(data, pointer))
            break
        else:
            # Label
            label = data[offset:offset+length].decode('ascii') # HINT
            offset += length
            name_parts.append(label)
    return '.'.join(name_parts)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send a DNS query and parse the reply.')
    parser.add_argument('--type', choices=['A', 'AAAA'], required=True, help='the type of address requested')
    parser.add_argument('--name', required=True, help='the host name being queried')
    parser.add_argument('--server', required=True, help='the IP address of the DNS server to query')
    args = parser.parse_args()

    result = dns_query(args.type, args.name, args.server)
