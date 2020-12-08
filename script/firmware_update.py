#!/usr/bin/python
import os
import sys
import serial
import time

def printStdErr(*objs):
#    print("", *objs, file=stderr)
#    print("")
    pass

def asbyte(v):
    return chr(v & 0xFF)



class LightYModem:
    """
    Receive_Packet
    - first byte SOH/STX (for 128/1024 byte size packets)
    - EOT (end)
    - CA CA abort
    - ABORT1 or ABORT2 is abort

    Then 2 bytes for seq-no (although the sequence number isn't checked)

    Then the packet data

    Then CRC16?

    First packet sent is a filename packet:
    - zero-terminated filename
    - file size (ascii) followed by space?
    """

    soh = 1     # 128 byte blocks
    stx = 2     # 1K blocks
    eot = 4
    ack = 6
    nak = 0x15
    ca =  0x18          # 24
    crc16 = 0x43        # 67
    abort1 = 0x41       # 65
    abort2 = 0x61       # 97

    packet_len = 1024
    expected_packet_len = packet_len+5
    packet_mark = stx

    def __init__(self):
        self.seq = None
        self.ymodem = None

    # For CRC algorithm
    crctable = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
    ]

    # CRC algorithm: CCITT-0
    def calc_crc(self, data, crc=0):
        for char in bytearray(data):
            crctbl_idx = ((crc >> 8) ^ char) & 0xff
            crc = ((crc << 8) ^ self.crctable[crctbl_idx]) & 0xffff
        return crc & 0xffff

    # Make check code
    def _make_send_checksum(self, data):
        _bytes = []
        crc = self.calc_crc(data)
        _bytes.extend([crc >> 8, crc & 0xff])
        return bytearray(_bytes)

    def flush(self):
        pass
        #self.ymodem.flush()

    def blocking_read(self):
        ch = ''
        while not ch:
            ch = self.ymodem.read(1)
        return ch

    def _read_response(self):
        ch1 = self.blocking_read()
        ch1 = ord(ch1)

        if ch1==LightYModem.ack and self.seq==0:    # may send also a crc16
            ch2 = self.blocking_read()
        elif ch1==LightYModem.ca:                   # cancel, always sent in pairs
            ch2 = self.blocking_read()
        return ch1

    def write(self, packet):
        for x in range(len(packet)):
            self.ymodem.write(packet[x])

        return len(packet);

    def _send_ymodem_packet(self, data):
        # pad string to 1024 chars
        data = data.ljust(LightYModem.packet_len)
        seqchr = asbyte(self.seq & 0xFF)
        seqchr_neg = asbyte((-self.seq-1) & 0xFF)
        crc_byte = self._make_send_checksum(data)
        packet = asbyte(LightYModem.packet_mark) + seqchr + seqchr_neg + data + chr(crc_byte[0]) + chr(crc_byte[1])
        if len(packet)!=LightYModem.expected_packet_len:
            raise Exception("packet length is wrong!")

        written = self.write(packet)
        self.flush()
        response = self._read_response()
        if response==LightYModem.ack:
            # ("sent packet nr %d " % (self.seq))
            self.seq += 1
        return response

    def _send_close(self):
        self.ymodem.write(asbyte(LightYModem.eot))
        self.flush()
        response = self._read_response()
        if response == LightYModem.ack:
            self.send_filename_header("", 0)

    def send_packet(self, file, output):
        response = LightYModem.eot
        data = file.read(LightYModem.packet_len)
        if len(data):
            response = self._send_ymodem_packet(data)
        return response

    def send_filename_header(self, name, size):
        self.seq = 0
        packet = name + asbyte(0) + str(size) + ' '
        return self._send_ymodem_packet(packet)

    def transfer(self, file, ymodem, output):
        self.ymodem = ymodem
        """
        file: the file to transfer via ymodem
        ymodem: the ymodem endpoint (a file-like object supporting write)
        output: a stream for output messages
        """

        file.seek(0, os.SEEK_END)
        size = file.tell()
	file.seek(0, os.SEEK_SET)
	LightYModem.packet_len = 128
	LightYModem.expected_packet_len = LightYModem.packet_len+5       
	LightYModem.packet_mark = self.soh
	response = self.send_filename_header("firmware", size)
	LightYModem.packet_len = 1024
	LightYModem.expected_packet_len = LightYModem.packet_len+5
	LightYModem.packet_mark = self.stx
        while response==LightYModem.ack:
            response = self.send_packet(file, output)
	    print("response+"response)

        file.close()
        if response==LightYModem.eot:
            self._send_close()

        return response



def ymodem(args):
    port = args[1]
    filename = args[2]
    infoend = "==========================================================\r\n"
    try:
	ser = serial.Serial(port, baudrate=115200)
    except:
	print("Can not Open Serial "+args[1])
	sys.exit(0)
    try:
	file = open(filename, 'rb')
    except:
	print("Can not Open Firmware File "+args[2])
   	sys.exit(0)
    print("Waiting Connection...")   
    print("Please Press Update Key")   
    while True:
        length = ser.in_waiting
        if length:
            data = ser.readline()
            if cmp(infoend,data) == 0 :
                print("Start Update...")
                break
    while True:
        string = "%d"%1
        ser.write(string)
	time.sleep(0.1)
        if ser.in_waiting != 0:
           data = ser.readline()
           if data.find("Waiting") != -1:
               break

    while True:
        data = ser.read_all()
        if data.find("C") != -1:
            break
    result = LightYModem().transfer(file, ser, sys.stderr)
    file.close()

    while True:
	if ser.in_waiting:
		data = ser.readline()
		if cmp(infoend,data) == 0 :
			break
    #print("Complete Update")
    while True:
        string = "%d"%3
        ser.write(string)
        time.sleep(0.1)
        if ser.in_waiting != 0:
            data = ser.readline()
            if data.find("Start") != -1:
                break
    ser.close()
    print("Firmware Update Done")

if __name__ == '__main__':
    ymodem(sys.argv)

