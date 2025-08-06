
#import serial
import telnetlib
import threading
import keyboard
import socket

FirstTime_1004 = True

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
    # Dichiara che vuoi usare la variabile globale, non una locale
    global FirstTime_1004

    if not data or data[0] != 0x01 or len(data) < 4:
        return

    opcode = data[1] | (data[2] << 8)
    param_len = data[3]
    params = data[4:4+param_len]

    print(f"Ricevuto opcode: 0x{opcode:04X}")

    response = None

    # Specific simulations
    if opcode == 0x0401: 
        # First send the Command Status event
        response = build_cmd_status(opcode)
        socket.sendall(response)

        # Extended Inquiry Response Data (240 bytes)
        eir_name = b'\x09\x09\x4D\x79\x44\x65\x76\x69\x63\x65' # Len:9 Type:09 Name:'MyDevice'
        eir_tx_power = b'\x02\x0A\x0C' # Len:2 Type:0A TX Power: 12 dBm
        # Services: Remote Control Target|Audio Source|Remote Control|Audio Sink|HandsFree Audio Gateway|HandsFree
        eir_services = b'\x0D\x03\x0C\x11\x0A\x11\x0E\x11\x0B\x11\x1F\x11\x1E\x11' # Len:13 Type:03 Services (16bit UUIDs) in little-endian

        # Calculate padding and create the full EIR data block
        eir_data = eir_name + eir_tx_power + eir_services
        eir_padding_len = 240 - len(eir_data)
        eir_padding = b'\x00' * eir_padding_len
        
        # Build the complete HCI Extended Inquiry Result packet
        hci_extended_inquiry_result = bytes([
            0x04,       # HCI Packet Type: Event (H4 = 0x04)
            0x2F,       # Event Code: Extended Inquiry Result
            0xFF,       # Parameter Total Length (255 bytes)

            0x01,                   # Num_Responses
            0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, # BD_ADDR (LSB first)
            0x01,                   # Page_Scan_Repetition_Mode
            0x00,                   # Reserved
            0x0C, 0x02, 0x5A,       # Class_of_Device
            0x00, 0x00,             # Clock_Offset (little endian)
            0xD8,                   # RSSI (-40 decimal)
        ]) + eir_data + eir_padding
        
        socket.sendall(hci_extended_inquiry_result)

        # Generate and send the Inquiry Complete event
        hci_inquiry_complete = bytes([
            0x04,       # HCI Packet Type: Event (H4 = 0x04)
            0x01,       # Event Code: Inquiry Complete
            0x01,       # Parameter Total Length (1 byte)
            0x00,       # Status: SUCCESS
        ])
        socket.sendall(hci_inquiry_complete)

        response = None
    elif opcode == 0x080F: 
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C01:  # HCI_SetEventMask
        # Expected parameters: 8 bytes
        if len(params) == 8:
            response = build_cmd_complete(opcode)
        else:
            print("Set_Event_Mask: invalid parameters")
            response = build_cmd_complete(opcode, b'\x01')  # Status != SUCCESS
    elif opcode == 0x0C03:  # HCI_Reset
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C0C:  # HCI_Change_Local_Name
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C1A:  # HCI_Change_Local_Name
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
    elif opcode == 0x0C18:  # HCI_Write_Default_Link_Policy_Settings
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C1A:  # HCI_Write_Simple_Pairing_Mode
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C1F:  # HCI_Write_Authentication_Enable
        response = build_cmd_complete(opcode)
    elif opcode == 0x0C20:  # HCI_Write_Authentication_Enable
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
        # Any value received, we respond with success
        response = build_cmd_complete(opcode, b'')
    elif opcode == 0x0C58:  # HCI_Read_Inquiry_Response_Transmit_Power_Level
        # Example: returns +4 dBm
        response = build_cmd_complete(opcode, b'\x04')
    elif opcode == 0x0C5A:  # HCI_Read_Default_Err_Data_Reporting
        response = build_cmd_complete(opcode, b'\x00')
    elif opcode == 0x0C63:  # HCI_Set_Event_Mask_Page_2
        if len(params) == 8:
            response = build_cmd_complete(opcode)
        else:
            print("Set_Event_Mask_Page_2: invalid parameters")
            response = build_cmd_complete(opcode, b'\x01')  # Generic error
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
        #socket.sendall("ciao".encode())

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
            #print(f"Letti {len(data)} byte: {data.hex()} | ASCII: {data.decode(errors='replace')}")

            #continue

            #if len(data):
            #print(data.decode(errors='ignore'), end='')
            #print(f"Letti {len(data)} byte: {data.hex()}")
            buffer.extend(data)  # <-- aggiungi i dati ricevuti al buffer

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
    #main2()
    connect_and_read("10.0.9.138", 12345)
