
import sys

if len(sys.argv) < 2:
    print('Enter the dump file name.')
    exit(0)

try:
    with open(sys.argv[1]) as f:
        tcp_rec = f.read()

except FileNotFoundError:
    print('Enter the proper text file name.')
    exit(0)

tcp_split = tcp_rec.split('|')[2:][14:][20:]

length = len(tcp_split)

tcp_rec = ' '.join(tcp_split)
print('\n\nOriginal TCP received : ', tcp_rec)
print('\nThe total TCP packet/header is of', length, 'bytes')

# source port address = 16 bits
source_port_address = int(tcp_split[0] + tcp_split[1], 16)
print('\n\nThe source port address is', source_port_address)

# destination port address = 16 bits
destination_port_address = int(tcp_split[2] + tcp_split[3], 16)
print('The destination port address is', destination_port_address)

# sequence number = 32 bits
sequence_number = int(
    tcp_split[4] + tcp_split[5] + tcp_split[6] + tcp_split[7], 16)
print('The sequence_number is', sequence_number)

# ack number = 32 bits
ack_number = int(
    tcp_split[8] + tcp_split[9] + tcp_split[10] + tcp_split[11], 16)
print('The acknowledgement number is', ack_number)

# header length = 4 bits
hlen = int(tcp_split[12][0], 16) * 4
print('The header length is', hlen)
print('Payload length is', length - hlen)
# reserved length = 6 bits
# reversed = int(tcp_split[12][1], 16) + bin(int(tcp_split[13][0], 16))
if(int(tcp_split[12][1]) == 0):
    print('Reserved bits are empty')

# flags length = 6 bits
# urg - urgent
# ack - acknowledgement
# psh - push
# rst - reset
# syn - synchronize
# fin - finished

print('\nFlag Bits\n')

flag_in_bin = bin(int(tcp_split[13], 16))[2:]
if len(flag_in_bin) > 6:
    flag_in_bin = flag_in_bin[len(flag_in_bin)-6:]

match len(flag_in_bin):
    case 0:
        print('No flag is set')

    case 1:
        if flag_in_bin[0] == '1':
            print('Connection termination flag is set')
        else:
            print('Connection termination flag is not set')

        print('Urgent pointer is valid is not set')
        print('Acknowledgment is valid is not set')
        print('Request for push flag is not set')
        print('Reset the connection flag is not set')
        print('Synchronize sequence numbers flag is not set')

    case 2:
        if flag_in_bin[0] == '1':
            print('Synchronize sequence numbers flag is set')
        else:
            print('Synchronize sequence numbers flag is not set')

        if flag_in_bin[1] == '1':
            print('Connection termination flag is set')
        else:
            print('Connection termination flag is not set')

        print('Urgent pointer is valid is not set')
        print('Acknowledgment is valid is not set')
        print('Request for push flag is not set')
        print('Reset the connection flag is not set')

    case 3:
        if flag_in_bin[0] == '1':
            print('Reset the connection flag is set')
        else:
            print('Reset the connection flag is not set')

        if flag_in_bin[1] == '1':
            print('Synchronize sequence numbers flag is set')
        else:
            print('Synchronize sequence numbers flag is not set')

        if flag_in_bin[2] == '1':
            print('Connection termination flag is set')
        else:
            print('Connection termination flag is not set')

        print('Urgent pointer is valid is not set')
        print('Acknowledgment is valid is not set')
        print('Request for push flag is not set')

    case 4:
        if flag_in_bin[0] == '1':
            print('Request for push flag is set')
        else:
            print('Request for push flag is not set')

        if flag_in_bin[1] == '1':
            print('Reset the connection flag is set')
        else:
            print('Reset the connection flag is not set')

        if flag_in_bin[2] == '1':
            print('Synchronize sequence numbers flag is set')
        else:
            print('Synchronize sequence numbers flag is not set')

        if flag_in_bin[3] == '1':
            print('Connection termination flag is set')
        else:
            print('Connection termination flag is not set')

        print('Urgent pointer is valid is not set')
        print('Acknowledgment is valid is not set')

    case 5:
        if flag_in_bin[0] == '1':
            print('Acknowledgment is valid flag is set')
        else:
            print('Acknowledgment is valid is not set')

        if flag_in_bin[1] == '1':
            print('Request for push flag is set')
        else:
            print('Request for push flag is not set')

        if flag_in_bin[2] == '1':
            print('Reset the connection flag is set')
        else:
            print('Reset the connection flag is not set')

        if flag_in_bin[3] == '1':
            print('Synchronize sequence numbers flag is set')
        else:
            print('Synchronize sequence numbers flag is not set')

        if flag_in_bin[4] == '1':
            print('Connection termination flag is set')
        else:
            print('Connection termination flag is not set')

        print('Urgent pointer is valid is not set')

    case 6:
        if flag_in_bin[0] == '1':
            print('Urgent pointer is valid flag is set')
        else:
            print('Urgent pointer is valid is not set')

        if flag_in_bin[1] == '1':
            print('Acknowledgment is valid flag is set')
        else:
            print('Acknowledgment is valid is not set')

        if flag_in_bin[2] == '1':
            print('Request for push flag is set')
        else:
            print('Request for push flag is not set')

        if flag_in_bin[3] == '1':
            print('Reset the connection flag is set')
        else:
            print('Reset the connection flag is not set')

        if flag_in_bin[4] == '1':
            print('Synchronize sequence numbers flag is set')
        else:
            print('Synchronize sequence numbers flag is not set')

        if flag_in_bin[5] == '1':
            print('Connection termination flag is set')
        else:
            print('Connection termination flag is not set')


# window size = 16 bits
window_size = int(tcp_split[15] + tcp_split[16], 16)
print('The window size is', window_size)

# checksum = 16 bits
checksum = int(tcp_split[17] + tcp_split[18], 16)
print('The checksum value is', checksum)

# urgent pointer = 16 bits
urgent_pointer_value = int(tcp_split[19] + tcp_split[20], 16)
print('The urgent pointer value is', urgent_pointer_value)

# options and padding = 0<l<40
# remaining playload
