#import serial
import telnetlib
import threading
import keyboard
import socket

FirstTime_1004 = True
FirstTime_041C = True

def print_hex(data):
    print(" ".join(f"{b:02x}" for b in data))

def write(fd, data):
    fd.write(bytes(data))
    fd.flush()

def build_cmd_complete(opcode, return_params=b''):
    packet_type = b'\x04'
    event_code = b'\x0E'
    num_hci_command_packets = b'\x01'
    opcode_bytes = opcode.to_bytes(2, 'little')
    status = b'\x00'
    param_total_length = (len(num_hci_command_packets) + len(opcode_bytes) + len(status) + len(return_params)).to_bytes(1, 'little')
    return packet_type + event_code + param_total_length + num_hci_command_packets + opcode_bytes + status + return_params

def build_cmd_status(opcode):
    packet_type = b'\x04'
    event_code = b'\x0F'
    param_total_length = b'\x04'
    status = b'\x00'
    num_hci_command_packets = b'\x01'
    opcode_bytes = opcode.to_bytes(2, 'little')
    return packet_type + event_code + param_total_length + status + num_hci_command_packets + opcode_bytes

def parse_hci_packet(data, socket):
    global FirstTime_1004
    global FirstTime_041C

    if not data or data[0] != 0x01 or len(data) < 4:
        return

    opcode = data[1] | (data[2] << 8)
    param_len = data[3]
    params = data[4:4+param_len]

    print(f"Ricevuto opcode: 0x{opcode:04X}")

    response = None

    if opcode == 0x0401:  # HCI_Inquiry
        response = build_cmd_status(opcode)
        socket.sendall(response)

        eir_name = b'\x09\x09\x4D\x79\x44\x65\x76\x69\x63\x65'
        eir_tx_power = b'\x02\x0A\x0C'
        eir_services = b'\x0D\x03\x0C\x11\x0A\x11\x0E\x11\x0B\x11\x1F\x11\x1E\x11'

        eir_data = eir_name + eir_tx_power + eir_services
        eir_padding_len = 240 - len(eir_data)
        eir_padding = b'\x00' * eir_padding_len
        
        hci_extended_inquiry_result = bytes([
            0x04, 0x2F, 0xFF, 0x01, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0x01, 0x00, 0x0C, 0x02, 0x5A, 0x00, 0x00, 0xD8,
        ]) + eir_data + eir_padding
        socket.sendall(hci_extended_inquiry_result)

        hci_inquiry_complete = bytes([0x04, 0x01, 0x01, 0x00])
        socket.sendall(hci_inquiry_complete)
        response = None
    
    elif opcode == 0x0405: # HCI_Create_Connection
        socket.sendall(build_cmd_status(opcode))
        
        hci_connection_complete = bytes([
            0x04, 0x03, 0x0B, 0x00, 0x01, 0x00, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0x01, 0x00,
        ])
        socket.sendall(hci_connection_complete)
        response = None

    elif opcode == 0x0406: # HCC_DISCONNECT
        response = build_cmd_status(opcode)
        socket.sendall(response)
        
        hci_num_completed_packets_1 = bytes([0x04, 0x13, 0x05, 0x01, 0x01, 0x00, 0x01, 0x00])
        socket.sendall(hci_num_completed_packets_1)
        
        hci_num_completed_packets_2 = bytes([0x04, 0x13, 0x05, 0x01, 0x01, 0x00, 0x01, 0x00])
        socket.sendall(hci_num_completed_packets_2)
        
        hci_num_completed_packets_3 = bytes([0x04, 0x13, 0x05, 0x01, 0x01, 0x00, 0x02, 0x00])
        socket.sendall(hci_num_completed_packets_3)

        hci_disconnect_complete = bytes([0x04, 0x05, 0x04, 0x00, 0x01, 0x00, 0x16])
        socket.sendall(hci_disconnect_complete)

        response = None
    
    elif opcode == 0x040B: # HCC_LINK_KEY_REQ_REPL
        hci_num_completed_packets_1 = bytes([0x04, 0x13, 0x05, 0x01, 0x01, 0x00, 0x01, 0x00])
        socket.sendall(hci_num_completed_packets_1)
        
        response = build_cmd_complete(opcode, b'\x41\x3c\x91\x3d\xe1\x38')
        
        hci_num_completed_packets_2 = bytes([0x04, 0x13, 0x05, 0x01, 0x01, 0x00, 0x01, 0x00])
        socket.sendall(hci_num_completed_packets_2)
        
        hci_auth_complete = bytes([0x04, 0x06, 0x03, 0x00, 0x01, 0x00])
        socket.sendall(hci_auth_complete)

    elif opcode == 0x040C:  # HCC_LINK_KEY_REQ_NEG_REPL
        response = build_cmd_complete(opcode, b'\xf6\xe5\xd4\xc3\xb2\xa1')
        socket.sendall(response)
        
        hci_io_capability_req = bytes([0x04, 0x31, 0x06, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1])
        socket.sendall(hci_io_capability_req)
        response = None

    elif opcode == 0x040F:  # HCC_CHNG_CONN_PACKET_TYPE
        response = build_cmd_complete(opcode, b'\x01\x00') # Connection Handle 0x0001

    elif opcode == 0x0411:  # HCC_AUTH_REQ
        socket.sendall(build_cmd_status(opcode))

        hci_link_key_req = bytes([0x04, 0x17, 0x07, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0x01])
        socket.sendall(hci_link_key_req)
        
        hci_num_completed_packets = bytes([0x04, 0x13, 0x05, 0x01, 0x01, 0x00, 0x01, 0x00])
        socket.sendall(hci_num_completed_packets)
        
        response = None

    elif opcode == 0x042B: # HCC_IO_CAPABILITY_RESPONSE
        response = build_cmd_complete(opcode, b'\xf6\xe5\xd4\xc3\xb2\xa1')
        socket.sendall(response)
        
        hci_num_completed_packets = bytes([0x04, 0x13, 0x05, 0x01, 0x01, 0x00, 0x01, 0x00])
        socket.sendall(hci_num_completed_packets)
        
        hci_io_capability_response = bytes([0x04, 0x32, 0x09, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0x01, 0x00, 0x01])
        socket.sendall(hci_io_capability_response)

        hci_user_confirmation_req = bytes([0x04, 0x33, 0x0A, 0xf6, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0x54, 0x42, 0x02, 0x00])
        socket.sendall(hci_user_confirmation_req)


        response = None

    elif opcode == 0x042C: # HCC_USER_CONFIRM_REQ_REPL
        response = build_cmd_complete(opcode, b'\xf6\xe5\xd4\xc3\xb2\xa1')
        socket.sendall(response)
        
        hci_simple_pairing_complete = bytes([0x04, 0x36, 0x07, 0x00, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1])
        socket.sendall(hci_simple_pairing_complete)

        hci_link_key_notify = bytes([0x04, 0x18, 0x17, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0x38, 0x7B, 0x70, 0x8D, 0xB9, 0xAF, 0xDA, 0x29, 0x9E, 0xE9, 0x87, 0x17, 0x71, 0x97, 0xBB, 0xE8, 0x05])
        socket.sendall(hci_link_key_notify)
        
        hci_auth_complete = bytes([0x04, 0x06, 0x03, 0x00, 0x01, 0x00])
        socket.sendall(hci_auth_complete)

        response = None
    
    elif opcode == 0x0419:  # HCI_Remote_Name_Request
        socket.sendall(build_cmd_status(opcode))
        
        remote_name_bytes = b'MyDevice'
        padding = b'\x00' * (248 - len(remote_name_bytes))
        hci_remote_name_req_complete = bytes([
            0x04, 0x07, 0xFF, 0x00, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1,
        ]) + remote_name_bytes + padding
        socket.sendall(hci_remote_name_req_complete)
        response = None
    
    elif opcode == 0x041B: # HCC_READ_REMOTE_FEATURES
        socket.sendall(build_cmd_status(opcode))
        
        hci_read_remote_features_complete = bytes([
            0x04, 0x0B, 0x0B, 0x00, 0x01, 0x00, 0xbf, 0xfe, 0xcf, 0xfe, 0xdb, 0xff, 0x7b, 0x87,
        ])
        socket.sendall(hci_read_remote_features_complete)
        response = None
    
    elif opcode == 0x041C: # HCC_READ_REMOTE_EXT_FEATURES
        socket.sendall(build_cmd_status(opcode))
        
        if FirstTime_041C == True:
            FirstTime_041C = False
            hci_read_remote_ext_features_complete = bytes([
                0x04, 0x23, 0x0D, 0x00, 0x01, 0x00, 0x01, 0x02, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
        else:
            hci_read_remote_ext_features_complete = bytes([
                0x04, 0x23, 0x0D, 0x00, 0x01, 0x00, 0x02, 0x02, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])

        socket.sendall(hci_read_remote_ext_features_complete)
        response = None
    
    elif opcode == 0x080D: # HCC_WRITE_LINK_POLICY_SETTINGS
        response = build_cmd_complete(opcode, b'\x01\x00') # Connection Handle 0x0001
    
    elif opcode == 0x0C18:  # HCC_WRITE_DEFAULT_LINK_POLICY_SETTINGS
        response = build_cmd_complete(opcode)
    
    elif opcode == 0x0C1C: # HCC_WRITE_PAGE_SCAN_ACTIVITY
        response = build_cmd_complete(opcode)
        
    elif opcode == 0x0C1E: # HCC_WRITE_INQ_SCAN_ACTIVITY
        response = build_cmd_complete(opcode)

    elif opcode == 0x0C2D:  # HCI_Write_PIN_Type
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C20:  # HCI_Write_Authentication_Enable
        response = build_cmd_complete(opcode)
    
    elif opcode == 0x080F: 
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C01:  # HCI_SetEventMask
        if len(params) == 8:
            response = build_cmd_complete(opcode)
        else:
            print("Set_Event_Mask: invalid parameters")
            response = build_cmd_complete(opcode, b'\x01')
    elif opcode == 0x0C03:  # HCI_Reset
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C0C:  # HCI_Change_Local_Name
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C1A:  # HCI_Write_Simple_Pairing_Mode
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C13:  
        response = build_cmd_complete(opcode, b'\
\x46\x65\x72\x72\x69\x74\x65\x48\x6f\x6d\x65\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\
')  
    elif opcode == 0x0C17:  # HCI_Change_Connection_Packet_Type
        response = build_cmd_complete(opcode, b'\x00\x20')
    elif opcode == 0x0C1A:  # HCI_Write_Simple_Pairing_Mode
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C24:  # HCI_Write_Class_of_Device
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C33:  # HCI_Write_Page_Scan_Activity
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C44:  # HCI_Read_Inquiry_Mode
        response = build_cmd_complete(opcode, b'\x00')
    elif opcode == 0x0C45:  # HCI_Write_Event_Mask
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C46:  # HCI_Write_Event_Mask_Page_2
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C51:  # HCI_Write_Scan_Enable
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C52:  # HCI_Write_Scan_Enable
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C55:  # HCI_Write_Page_Timeout
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C56:  # HCI_Write_Simple_Pairing_Mode
        response = build_cmd_complete(opcode, b'')
    elif opcode == 0x0C58:  # HCI_Read_Inquiry_Response_Transmit_Power_Level
        response = build_cmd_complete(opcode, b'\x04')
    elif opcode == 0x0C5A:  # HCI_Read_Default_Err_Data_Reporting
        response = build_cmd_complete(opcode, b'\x00')
    elif opcode == 0x0C63:  # HCI_Set_Event_Mask_Page_2
        if len(params) == 8:
            response = build_cmd_complete(opcode)
        else:
            print("Set_Event_Mask_Page_2: invalid parameters")
            response = build_cmd_complete(opcode, b'\x01')
    elif opcode == 0x1001:  # HCI_Read_Local_Name
        response = build_cmd_complete(opcode, b'\x0b\x00\x83\x0b\x48\x00\x45\x75')
    elif opcode == 0x1002:  # HCI_Read_Local_Supported_Commands
        response = build_cmd_complete(opcode, b'\
\xFF\xFF\xFF\x03\xCE\xFF\xEF\xFF\xFF\xFF\xEF\x1F\xF2\x0F\xE8\xFE\
\x3F\xF7\x8F\xFF\x1C\x00\x04\x00\x61\xF7\xFF\xFF\x7F\xFE\x23\xF5\
\x81\x0F\xFE\x07\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
')                              
    elif opcode == 0x1003:  # HCI_Read_Local_Features
        response = build_cmd_complete(opcode, b'\xFF\xFE\x8F\xFE\xDB\xFF\x7B\x87')
    elif opcode == 0x1004:  # HCI_Read_Local_Extended_Features
        if FirstTime_1004 == True:
            FirstTime_1004 = False
            response = build_cmd_complete(opcode, b'\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00')
        else:
            response = build_cmd_complete(opcode, b'\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00')
    elif opcode == 0x1005:  # HCI_Read_Buffer_Size
        response = build_cmd_complete(opcode, b'\xFD\x03\x78\x07\x00\x06\x00')
    elif opcode == 0x1009:  # HCI_Read_BD_ADDR
        response = build_cmd_complete(opcode, b'\xE0\x59\x2B\x2A\xF8\x54')
    elif opcode == 0x100B:
        response = build_cmd_complete(opcode, b'\x05\x00\x01\x02\x05\x00')
    elif opcode == 0x100C:
        response = build_cmd_complete(opcode, b'\x01\x10')
    elif opcode == 0xFC1D:  # Vendor Specific
        response = build_cmd_complete(opcode)
    elif opcode == 0xFC26:  # Vendor Specific
        response = build_cmd_complete(opcode, b'\x01')
    elif opcode == 0xFC73:  # Vendor Specific
        response = build_cmd_complete(opcode)
    elif opcode == 0xFC79:  # Vendor Specific
        response = build_cmd_complete(opcode)
    elif opcode == 0xFC7A:  # Vendor Specific
        response = build_cmd_complete(opcode)
    else:
        print(f"HCI unsupported command: opcode 0x{opcode:04X}")
        #response = build_cmd_complete(opcode)

    if response:
        print(f"Invio response ({len(response)} byte): {response.hex()}")
        socket.sendall(response)

def connect_and_read(ip, port):
    buffer = bytearray()
    buffer.clear()
    expected_len = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        print(f"Connesso a {ip}:{port}")
        while True:
            data = s.recv(1)
            if not data:
                print("Connessione chiusa dal server.")
                break
            buffer.extend(data)

            if len(buffer) == 1:
                if buffer[0] == 0x01:
                    expected_len = 4
                elif buffer[0] == 0x02:
                    expected_len = 5
                elif buffer[0] == 0x04:
                    expected_len = 3
                else:
                    print(f"Pacchetto HCI tipo sconosciuto o errato: 0x{buffer[0]:02x}")
                    buffer.clear()
                    expected_len = 0
            elif len(buffer) == expected_len:
                pkt_type = buffer[0]
                if pkt_type == 0x01 and expected_len == 4:
                    expected_len += buffer[3]
                elif pkt_type == 0x02 and expected_len == 5:
                    expected_len += buffer[3] | (buffer[4] << 8)
                elif pkt_type == 0x04 and expected_len == 3:
                    expected_len += buffer[2]


            if expected_len and len(buffer) == expected_len:
                parse_hci_packet(buffer,s)
                buffer.clear()
                expected_len = 0

if __name__ == "__main__":
    connect_and_read("192.168.1.111", 12345)