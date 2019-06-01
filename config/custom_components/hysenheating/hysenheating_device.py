"""
Class Broadlink device
Based on the work from
https://github.com/mjg59/python-broadlink
"""

import random
import socket
import threading
import time
from PyCRC.CRC16 import CRC16

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    import pyaes

import logging

_LOGGER = logging.getLogger(__name__)

class broadlink_device:
    def __init__(self, host, mac, devtype, timeout=10):
        self.host = host
        self.mac = mac.encode() if isinstance(mac, str) else mac
        self.devtype = devtype
        self.timeout = timeout
        self.count = random.randrange(0xffff)
        self.iv = bytearray(
            [0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58])
        self.id = bytearray([0, 0, 0, 0])
        self.cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.cs.bind(('', 0))
        self.type = "Unknown"
        self.lock = threading.Lock()

        if 'pyaes' in globals():
            self.encrypt = self.encrypt_pyaes
            self.decrypt = self.decrypt_pyaes
            self.update_aes = self.update_aes_pyaes

        else:
            self.encrypt = self.encrypt_crypto
            self.decrypt = self.decrypt_crypto
            self.update_aes = self.update_aes_crypto

        self.aes = None
        key = bytearray(
            [0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02])
        self.update_aes(key)

    def update_aes_pyaes(self, key):
        self.aes = pyaes.AESModeOfOperationCBC(key, iv=bytes(self.iv))

    def encrypt_pyaes(self, payload):
        return b"".join([self.aes.encrypt(bytes(payload[i:i + 16])) for i in range(0, len(payload), 16)])

    def decrypt_pyaes(self, payload):
        return b"".join([self.aes.decrypt(bytes(payload[i:i + 16])) for i in range(0, len(payload), 16)])

    def update_aes_crypto(self, key):
        self.aes = Cipher(algorithms.AES(key), modes.CBC(self.iv),
                          backend=default_backend())

    def encrypt_crypto(self, payload):
        encryptor = self.aes.encryptor()
        return encryptor.update(payload) + encryptor.finalize()

    def decrypt_crypto(self, payload):
        decryptor = self.aes.decryptor()
        return decryptor.update(payload) + decryptor.finalize()

    def auth(self):
        payload = bytearray(0x50)
        payload[0x04] = 0x31
        payload[0x05] = 0x31
        payload[0x06] = 0x31
        payload[0x07] = 0x31
        payload[0x08] = 0x31
        payload[0x09] = 0x31
        payload[0x0a] = 0x31
        payload[0x0b] = 0x31
        payload[0x0c] = 0x31
        payload[0x0d] = 0x31
        payload[0x0e] = 0x31
        payload[0x0f] = 0x31
        payload[0x10] = 0x31
        payload[0x11] = 0x31
        payload[0x12] = 0x31
        payload[0x1e] = 0x01
        payload[0x2d] = 0x01
        payload[0x30] = ord('T')
        payload[0x31] = ord('e')
        payload[0x32] = ord('s')
        payload[0x33] = ord('t')
        payload[0x34] = ord(' ')
        payload[0x35] = ord(' ')
        payload[0x36] = ord('1')

        response = self.send_packet(0x65, payload)

        payload = self.decrypt(response[0x38:])

        if not payload:
            return False

        key = payload[0x04:0x14]
        if len(key) % 16 != 0:
            return False

        self.id = payload[0x00:0x04]
        self.update_aes(key)

        return True

    def send_packet(self, command, payload):
        self.count = (self.count + 1) & 0xffff
        packet = bytearray(0x38)
        packet[0x00] = 0x5a
        packet[0x01] = 0xa5
        packet[0x02] = 0xaa
        packet[0x03] = 0x55
        packet[0x04] = 0x5a
        packet[0x05] = 0xa5
        packet[0x06] = 0xaa
        packet[0x07] = 0x55
        packet[0x24] = 0x2a
        packet[0x25] = 0x27
        packet[0x26] = command
        packet[0x28] = self.count & 0xff
        packet[0x29] = self.count >> 8
        packet[0x2a] = self.mac[0]
        packet[0x2b] = self.mac[1]
        packet[0x2c] = self.mac[2]
        packet[0x2d] = self.mac[3]
        packet[0x2e] = self.mac[4]
        packet[0x2f] = self.mac[5]
        packet[0x30] = self.id[0]
        packet[0x31] = self.id[1]
        packet[0x32] = self.id[2]
        packet[0x33] = self.id[3]

        # pad the payload for AES encryption
        if payload:
            numpad = (len(payload) // 16 + 1) * 16
            payload = payload.ljust(numpad, b"\x00")

        checksum = 0xbeaf
        for i in range(len(payload)):
            checksum += payload[i]
            checksum = checksum & 0xffff

        payload = self.encrypt(payload)

        packet[0x34] = checksum & 0xff
        packet[0x35] = checksum >> 8

        for i in range(len(payload)):
            packet.append(payload[i])

        checksum = 0xbeaf
        for i in range(len(packet)):
            checksum += packet[i]
            checksum = checksum & 0xffff
        packet[0x20] = checksum & 0xff
        packet[0x21] = checksum >> 8

        start_time = time.time()
        with self.lock:
            while True:
                try:
                    self.cs.sendto(packet, self.host)
                    self.cs.settimeout(1)
                    response = self.cs.recvfrom(2048)
                    break
                except socket.timeout:
                    if (time.time() - start_time) > self.timeout:
                        raise
        return bytearray(response[0])

    # Send a request
    # Returns decrypted payload
    # Device's memory data is structured in an array of bytes, word (2 bytes) aligned
    # input_payload should be a bytearray
    # There are three known different request types (commands)
    # 1. write a word (2 bytes) at a given position (position counted in words)
    #    Command example
    #      0x01, 0x06, 0x00, 0x04, 0x28, 0x0A
    #      first byte 
    #        0x01 - header
    #      a byte representing command type
    #        0x06 - write word at a given position 
    #      an unknown byte (always 0x00)
    #        0x00
    #      a byte which is memory data word's index
    #        0x04 - the fifth word in memory data 
    #      the bytes to be written
    #        0x28, 0x0A - cooling max_temp (sh1) = 40, cooling min_temp (sl1) = 10
    #    No error confirmation response 
    #      0x01, 0x06, 0x00, 0x04, 0x28, 0x0A
    #      first byte 
    #        0x01 - header
    #      a byte representing command type
    #        0x06 - write word at a given position 
    #      an unknown byte (always 0x00)
    #        0x00
    #      a byte which is memory data word's index
    #        0x04 - the fifth word in memory data 
    #      the bytes written
    #        0x28, 0x0A - cooling max_temp (sh1) = 40, cooling min_temp (sl1) = 10
    # 2. write several words (multiple of 2 bytes) at a given position (position counted in words)
    #    Command example
    #      0x01, 0x10, 0x00, 0x07, 0x00, 0x02, 0x04, 0x08, 0x14, 0x10, 0x02
    #      first byte 
    #        0x01 - header
    #      a byte representing command type
    #        0x10 - write several words at a given position 
    #      an unknown byte (always 0x00)
    #        0x00
    #      a byte representing memory data word's index
    #        0x07 - the eighth word in memory data
    #      an unknown byte (always 0x00)
    #        0x00
    #      a byte representing the number of words (2 bytes) to be written
    #        0x02 - 2 words
    #      a byte representing the number of bytes to be written (previous word multiplied by 2)
    #        0x04 - 4 bytes
    #      the bytes to be written
    #        0x08, 0x14, 0x10, 0x02 - hour = 8, min = 20, sec = 10, weekday = 2 = Tuesday
    #    No error confirmation response
    #      0x01, 0x10, 0x00, 0x08, 0x00, 0x02
    #      first byte 
    #        0x01 - header
    #      a byte representing command type
    #        0x10 - write several words at a given position 
    #      an unknown byte (always 0x00)
    #        0x00
    #      a byte representing memory data word's index
    #        0x07 - the eighth word in memory data
    #      an unknown byte (always 0x00)
    #        0x00
    #      a byte representing the number of words (2 bytes) written
    #        0x02 - 2 words
    # 3. read memory data from a given position (position counted in words)
    #    Command example
    #      0x01, 0x03, 0x00, 0x07, 0x00, 0x02
    #      first byte 
    #        0x01 - header
    #      a byte representing command type
    #        0x03 - read several words at a given position 
    #      an unknown byte (always 0x00)
    #        0x00
    #      a byte representing memory data word's index
    #        0x07 - the eighth word in memory data
    #      a byte representing the number of words to be read
    #        0x02 - 2 words
    #    No error confirmation response
    #      0x01, 0x03, 0x04, 0x08, 0x14, 0x10, 0x02
    #      first byte 
    #        0x01 - header
    #      a byte representing command type
    #        0x03 - read command 
    #      a byte representing the number of bytes read
    #        0x04 - 4 bytes 
    #      the memory data bytes
    #        0x08, 0x14, 0x10, 0x02 - hour = 8, min = 20, sec = 10, weekday = 2 = Tuesday
    # Error responses for any command type
    #      0x01, 0xXX, 0xYY where
    #      first byte 
    #        0x01 - header
    #      second byte - Most significant bit 1 (error), last significant bits is the command type
    #        e.g. 0x90 - error in command type 0x10
    #      third byte
    #        0xYY - error type
    #        0x01 - Unknown command
    #        0x02 - Length missing or too big
    #        0x03 - Wrong length
    # New behavior: raises a ValueError if the device response indicates an error or CRC check fails
    # The function prepends length (2 bytes) and appends CRC
    def send_request(self, input_payload):
        for i in range(1, 3):
            crc = CRC16(modbus_flag = True).calculate(bytes(input_payload))
            if crc == None:
                _LOGGER.error("[%s] CRC16 returned None, step %s.", self._host, i)
            else:
                break
                
        # first byte is length, +2 for CRC16
        request_payload = bytearray([len(input_payload) + 2,0x00])
        request_payload.extend(input_payload)

        # append CRC
        request_payload.append(crc & 0xFF)
        request_payload.append((crc >> 8) & 0xFF)

        # send to device
        response = self.send_packet(0x6a, request_payload)

        # check for error
        err = response[0x22] | (response[0x23] << 8)
        if err:
            raise ValueError('broadlink_response_error',err)
      
        response_payload = bytearray(self.decrypt(bytes(response[0x38:])))
        
        # experimental check on CRC in response (first 2 bytes are len, and trailing bytes are crc)
        response_payload_len = response_payload[0]
        if response_payload_len + 2 > len(response_payload):
            raise ValueError('hysen_response_error','first byte of response is not length')
        crc = CRC16(modbus_flag=True).calculate(bytes(response_payload[2:response_payload_len]))
        if (response_payload[response_payload_len] == crc & 0xFF) and \
           (response_payload[response_payload_len+1] == (crc >> 8) & 0xFF):
            return_payload = response_payload[2:response_payload_len]
        else:
            raise ValueError('hysen_response_error','CRC check on response failed')
            
        # check if return response is right
        if (input_payload[0:2] == bytearray([0x01, 0x06])) and \
           (input_payload != return_payload):
            _LOGGER.error("[%s] request %s response %s",
                self.host,
                ' '.join(format(x, '02x') for x in bytearray(input_payload)),
                ' '.join(format(x, '02x') for x in bytearray(return_payload)))
            self.auth()
            raise ValueError('hysen_response_error','response is wrong')
        elif (input_payload[0:2] == bytearray([0x01, 0x10])) and \
             (input_payload[0:6] != return_payload):
            _LOGGER.error("[%s] request %s response %s",
                self.host,
                ' '.join(format(x, '02x') for x in bytearray(input_payload)),
                ' '.join(format(x, '02x') for x in bytearray(return_payload)))
            self.auth()
            raise ValueError('hysen_response_error','response is wrong')
        elif (input_payload[0:2] == bytearray([0x01, 0x03])) and \
             ((input_payload[0:2] != return_payload[0:2]) or \
             ((2 * input_payload[5]) != return_payload[2]) or \
             ((2 * input_payload[5]) != len(return_payload[3:]))):
            _LOGGER.error("[%s] request %s response %s",
                self.host,
                ' '.join(format(x, '02x') for x in bytearray(input_payload)),
                ' '.join(format(x, '02x') for x in bytearray(return_payload)))
            self.auth()
            raise ValueError('hysen_response_error','response is wrong')
        else:
            return return_payload

"""
Hysen Heating Thermostat Controller Interface
Hysen HY03-x-Wifi device and derivative
http://www.xmhysen.com/products_detail/productId=197.html
"""

HYSEN_HEAT_REMOTE_LOCK_OFF      = 0
HYSEN_HEAT_REMOTE_LOCK_ON       = 1

HYSEN_HEAT_POWER_OFF            = 0
HYSEN_HEAT_POWER_ON             = 1

HYSEN_HEAT_VALVE_OFF            = 0
HYSEN_HEAT_VALVE_ON             = 1

HYSEN_HEAT_MANUAL_OVER_AUTO_OFF = 0
HYSEN_HEAT_MANUAL_OVER_AUTO_ON  = 1

HYSEN_HEAT_MODE_MANUAL          = 0
HYSEN_HEAT_MODE_AUTO            = 1

HYSEN_HEAT_SCHEDULE_12345_67    = 1
HYSEN_HEAT_SCHEDULE_123456_7    = 2
HYSEN_HEAT_SCHEDULE_1234567     = 3

HYSEN_HEAT_SENSOR_INTERNAL      = 0
HYSEN_HEAT_SENSOR_EXTERNAL      = 1
HYSEN_HEAT_SENSOR_INT_EXT       = 2

HYSEN_HEAT_HYSTERESIS_MIN       = 1
HYSEN_HEAT_HYSTERESIS_MAX       = 9

HYSEN_HEAT_CALIBRATION_MIN      = -5.0
HYSEN_HEAT_CALIBRATION_MAX      = 5.0

HYSEN_HEAT_FROST_PROTECTION_OFF = 0
HYSEN_HEAT_FROST_PROTECTION_ON  = 1

HYSEN_HEAT_POWERON_OFF          = 0
HYSEN_HEAT_POWERON_ON           = 1

HYSEN_HEAT_MAX_TEMP             = 99
HYSEN_HEAT_MIN_TEMP             = 5

HYSEN_HEAT_DEFAULT_TARGET_TEMP  = 22
HYSEN_HEAT_DEFAULT_HYSTERESIS   = 2
HYSEN_HEAT_DEFAULT_CALIBRATION  = 0.0

class HysenHeatingDevice(broadlink_device):
    
    def __init__ (self, host, mac, devtype, timeout):
        broadlink_device.__init__(self, host, mac, devtype, timeout)
        self.type = "Hysen Heating Thermostat Controller"
        self._host = host[0]
        
        self.manual_target_temp = HYSEN_HEAT_DEFAULT_TARGET_TEMP
        self.remote_lock = HYSEN_HEAT_REMOTE_LOCK_OFF
        self.valve_state = HYSEN_HEAT_VALVE_OFF
        self.power_state = HYSEN_HEAT_POWER_ON
        self.manual_over_auto  = HYSEN_HEAT_MANUAL_OVER_AUTO_OFF
        self.room_temp = 0        
        self.target_temp = HYSEN_HEAT_DEFAULT_TARGET_TEMP
        self.operation_mode = HYSEN_HEAT_MODE_MANUAL
        self.schedule = HYSEN_HEAT_SCHEDULE_1234567
        self.sensor = HYSEN_HEAT_SENSOR_INTERNAL
        self.external_limit_temp = HYSEN_HEAT_DEFAULT_TARGET_TEMP
        self.hysteresis = HYSEN_HEAT_DEFAULT_HYSTERESIS
        self.max_temp = HYSEN_HEAT_MAX_TEMP
        self.min_temp = HYSEN_HEAT_MIN_TEMP
        self.calibration = HYSEN_HEAT_DEFAULT_CALIBRATION
        self.frost_protection = HYSEN_HEAT_FROST_PROTECTION_OFF
        self.poweron = HYSEN_HEAT_POWERON_OFF
        self.unknown1 = 0
        self.external_temp = 0
        self.clock_hour = 0
        self.clock_min = 0
        self.clock_sec = 0
        self.clock_weekday = 1
        self.period1_hour = 0
        self.period1_min = 0
        self.period2_hour_hour = 0
        self.period2_min = 0
        self.period3_hour = 0
        self.period3_min = 0
        self.period4_hour = 0
        self.period4_min = 0
        self.period5_hour = 0
        self.period5_min = 0
        self.period6_hour = 0
        self.period6_min = 0
        self.we_period1_hour = 0
        self.we_period1_min = 0
        self.we_period6_hour = 0
        self.we_period6_min = 0
        self.period1_temp = 0
        self.period2_temp = 0
        self.period3_temp = 0
        self.period4_temp = 0
        self.period5_temp = 0
        self.period6_temp = 0
        self.we_period1_temp = 0
        self.we_period6_temp = 0
        self.unknown2 = 0
        self.unknown3 = 0

    # set lock and power
    # 0x01, 0x06, 0x00, 0x00, 0x0r, 0xap
    # r = Remote lock, 0 = Off, 1 = On
    # a = Manual over Auto, 0 = Off, 1 = On
    # p = Power State, 0 = Power off, 1 = Power on
    # confirmation response:
    # response 0x01, 0x06, 0x00, 0x00, 0x0r, 0x0p
    def set_lock_power(self, remote_lock, power_state):
        _request = bytearray([0x01, 0x06, 0x00, 0x00])
        _request.append(remote_lock)
        _request.append(power_state)
        self.send_request(_request)

    def set_remote_lock(self, remote_lock):
        if remote_lock not in [
            HYSEN_HEAT_REMOTE_LOCK_OFF, 
            HYSEN_HEAT_REMOTE_LOCK_ON]:
            raise ValueError(
                'Can\'t set remote lock (%s) outside device\'s admitted values (%s), (%s).' % ( \
                remote_lock,
                HYSEN_HEAT_REMOTE_LOCK_OFF,
                HYSEN_HEAT_REMOTE_LOCK_ON))
        self.get_device_status()
        self.set_lock_power(
            remote_lock, 
            self.power_state)

    def set_power(self, power_state):
        if power_state not in [
            HYSEN_HEAT_POWER_OFF, 
            HYSEN_HEAT_POWER_ON]:
            raise ValueError(
                'Can\'t set power state (%s) outside device\'s admitted values (%s), (%s).' % ( \
                power_state,
                HYSEN_HEAT_POWER_OFF,
                HYSEN_HEAT_POWER_ON))
        self.get_device_status()
        self.set_lock_power(
            self.remote_lock, 
            power_state | (self.power_state & 0xFE))

    # set target temperature
    # 0x01,0x06,0x00,0x01,0x00, Tt
    # Tt = Target temperature in degrees Celsius * 2
    # confirmation response:
    # response 0x01,0x06,0x00,0x01,0x00,Tt
    # Note: If in automatic mode, setting temperature changes to manual mode
    def set_target_temp(self, temp):
        self.get_device_status()
        if temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                temp,
                self.max_temp))
        if temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                temp,
                self.min_temp))
        # if in operation mode manual, save the target temperature.
        # we'll need it to restore it at a later time, in case of manual over auto, then auto, then manual
        if (self.operation_mode == HYSEN_HEAT_MODE_MANUAL):
            self.manual_target_temp = temp
        _request = bytearray([0x01, 0x06, 0x00, 0x01])
        _request.append(0)
        _request.append(int(temp * 2))
        self.send_request(_request)

    # set mode, loop and sensor type
    # 0x01, 0x06, 0x00, 0x02, 0xlm, Sen
    # m = Operation mode, 0x00 = Manual, 0x01 = Auto
    # l = Loop mode, Weekly schedule, 0x01 = 12345,67, 0x02 = 123456,7, 0x03 = 1234567
    # Sen = sensor, 0x00 = internal, 0x01 = external, 0x02 = internal control with external target
    # confirmation response:
    # response 0x01, 0x06, 0x00, 0x02, 0xml, Sen
    # Note:  
    def set_mode_loop_sensor(self, operation_mode, schedule, sensor):
        _request = bytearray([0x01, 0x06, 0x00, 0x02])
        _request.append((schedule<<4) + operation_mode)
        _request.append(sensor)
        self.send_request(_request)

    def set_sensor(self, sensor):
        if sensor not in [
            HYSEN_HEAT_SENSOR_INTERNAL, 
            HYSEN_HEAT_SENSOR_EXTERNAL, 
            HYSEN_HEAT_SENSOR_INT_EXT]:
            raise ValueError(
                'Can\'t set sensor (%s) outside device\'s admitted values (%s), (%s), (%s).' % ( \
                sensor,
                HYSEN_HEAT_SENSOR_INTERNAL,
                HYSEN_HEAT_SENSOR_EXTERNAL, 
                HYSEN_HEAT_SENSOR_INT_EXT))
        self.get_device_status()
        self.set_mode_loop_sensor(
            self.operation_mode, 
            self.schedule, 
            sensor)
    
    def set_operation_mode(self, operation_mode):
        if operation_mode not in [
            HYSEN_HEAT_MODE_MANUAL, 
            HYSEN_HEAT_MODE_AUTO]:
            raise ValueError(
                'Can\'t set operation_mode (%s) outside device\'s admitted values (%s), (%s).' % ( \
                operation_mode,
                HYSEN_HEAT_MODE_MANUAL,
                HYSEN_HEAT_MODE_AUTO))
        self.get_device_status()
        self.set_mode_loop_sensor(
            operation_mode, 
            self.schedule, 
            self.sensor)
 
    def set_weekly_schedule(self, schedule):
        if schedule not in [
            HYSEN_HEAT_SCHEDULE_12345_67, 
            HYSEN_HEAT_SCHEDULE_123456_7, 
            HYSEN_HEAT_SCHEDULE_1234567]:
            raise ValueError(
                'Can\'t set schedule (%s) outside device\'s admitted values (%s), (%s), (%s).' % ( \
                schedule,
                HYSEN_HEAT_SCHEDULE_12345_67,
                HYSEN_HEAT_SCHEDULE_123456_7, 
                HYSEN_HEAT_SCHEDULE_1234567))
        self.get_device_status()
        self.set_mode_loop_sensor(
            self.operation_mode, 
            schedule, 
            self.sensor)
    
    # set options
    # 0x01, 0x10, 0x00, 0x03, 0x00, 0x04, 0x08, Osv, Dif, Svh, Svl, AdjMSB, AdjLSB, Fre, POn
    # Osv = Limit temperature external sensor
    # Dif = Hysteresis
    # Svh = Max. temperature internal sensor
    # Svl = Min. temperature internal sensor
    # Adj = Temperature calibration -5~+5, 0.1 degree Celsius step 
    #       (e.g. -1 = 0xFFF6, -1.4 = 0xFFF2, 0 = 0x0000, +1 = 0x000A, +1.2 = 0x000C, +2 = 0x0014, etc.)
    # Fre = Frost Protection, 0x00 = Off, 0x01 = On
    # POn = Power On, 0x00 = When powered, thermostat Off, 0x01 = When powered, thermostat On
    # confirmation response:
    # payload 0x01,0x10,0x00,0x03,0x00,0x08
    def set_options(self, external_limit_temp, hysteresis, max_temp, min_temp, calibration, frost_protection, poweron):
        calibration = int(calibration * 2)
        # Convert to signed byte
        calibration = (0x10000 + calibration) & 0xFFFF
        calibration_MSB = (calibration >> 8) & 0xFF
        calibration_LSB = calibration & 0xFF
        _request = bytearray([0x01, 0x10, 0x00, 0x03, 0x00, 0x04, 0x08])
        _request.append(int(external_limit_temp))
        _request.append(int(hysteresis))
        _request.append(max_temp)
        _request.append(min_temp)
        _request.append(calibration_MSB)
        _request.append(calibration_LSB)
        _request.append(frost_protection)
        _request.append(poweron)
        self.send_request(_request)

    def set_external_limit_temp(self, external_limit_temp):
        if external_limit_temp < HYSEN_HEAT_MIN_TEMP:
            raise ValueError(
                'Can\'t set external limit temperature (%s°) lower than device\'s minimum (%s°).' % ( \
                external_limit_temp,
                HYSEN_HEAT_MIN_TEMP))
        if external_limit_temp > HYSEN_HEAT_MAX_TEMP:
            raise ValueError(
                'Can\'t set external limit temperature (%s°) higher than device\'s maximum (%s°).' % ( \
                external_limit_temp,
                HYSEN_HEAT_MAX_TEMP))
        self.get_device_status()
        self.set_options(
            external_limit_temp,
            self.hysteresis, 
            self.max_temp,
            self.min_temp, 
            self.calibration, 
            self.frost_protection,
            self.poweron)

    def set_hysteresis(self, hysteresis):
        if hysteresis < HYSEN_HEAT_HYSTERESIS_MIN:
            raise ValueError(
                'Can\'t set hysteresis (%s°) lower than device\'s minimum (%s°).' % ( \
                hysteresis,
                HYSEN_HEAT_HYSTERESIS_MIN))
        if hysteresis > HYSEN_HEAT_HYSTERESIS_MAX:
            raise ValueError(
                'Can\'t set hysteresis (%s°) higher than device\'s maximum (%s°).' % ( \
                hysteresis,
                HYSEN_HEAT_HYSTERESIS_MAX))
        self.get_device_status()
        self.set_options(
            self.external_limit_temp,
            hysteresis, 
            self.max_temp,
            self.min_temp, 
            self.calibration, 
            self.frost_protection,
            self.poweron)

    def set_max_temp(self, temp):
        self.get_device_status()
        if temp > HYSEN_HEAT_MAX_TEMP:
            raise ValueError(
                'Can\'t set maximum temperature (%s°) higher than device\'s maximum (%s°).' % ( \
                temp,
                HYSEN_HEAT_MAX_TEMP))
        if temp < self.min_temp:
            raise ValueError(
                'Can\'t set maximum temperature (%s°) lower than minimum set (%s°).' % ( \
                temp,
                self.min_temp))
        if temp < self.target_temp:
            raise ValueError(
                'Can\'t set maximum temperature (%s°) lower than target temperature (%s°).' % ( \
                temp,
                self.target_temp))
        self.set_options(
            self.external_limit_temp,
            self.hysteresis, 
            temp,
            self.min_temp, 
            self.calibration, 
            self.frost_protection,
            self.poweron)

    def set_min_temp(self, temp):
        self.get_device_status()
        if temp < HYSEN_HEAT_MIN_TEMP:
            raise ValueError(
                'Can\'t set minimum temperature (%s°) lower than device\'s minimum (%s°).' % ( \
                temp,
                HYSEN_HEAT_MIN_TEMP))
        if temp > self.max_temp:
            raise ValueError(
                'Can\'t set minimum temperature (%s°) higher than maximum set (%s°).' % ( \
                temp,
                self.max_temp))
        if temp > self.target_temp:
            raise ValueError(
                'Can\'t set minimum temperature (%s°) higher than target temperature (%s°).' % ( \
                temp,
                self.target_temp))
        self.set_options(
            self.external_limit_temp,
            self.hysteresis, 
            self.max_temp,
            temp, 
            self.calibration, 
            self.frost_protection,
            self.poweron)

    def set_calibration(self, calibration):
        if calibration < HYSEN_HEAT_CALIBRATION_MIN:
            raise ValueError(
                'Can\'t set calibration (%s°) lower than device\'s minimum (%s°).' % ( \
                calibration,
                HYSEN_HEAT_CALIBRATION_MIN))
        if calibration > HYSEN_HEAT_CALIBRATION_MAX:
            raise ValueError(
                'Can\'t set calibration (%s°) higher than device\'s maximum (%s°).' % ( \
                calibration,
                HYSEN_HEAT_CALIBRATION_MAX))
        self.get_device_status()
        self.set_options(
            self.external_limit_temp,
            self.hysteresis, 
            self.max_temp,
            self.min_temp, 
            calibration, 
            self.frost_protection,
            self.poweron)

    def set_frost_protection(self, frost_protection):
        if frost_protection not in [
            HYSEN_HEAT_FROST_PROTECTION_OFF, 
            HYSEN_HEAT_FROST_PROTECTION_ON]:
            raise ValueError(
                'Can\'t set frost protection (%s) outside device\'s admitted values (%s), (%s).' % ( \
                frost_protection,
                HYSEN_HEAT_FROST_PROTECTION_OFF,
                HYSEN_HEAT_FROST_PROTECTION_ON))
        self.get_device_status()
        self.set_options(
            self.external_limit_temp,
            self.hysteresis, 
            self.max_temp,
            self.min_temp, 
            self.calibration, 
            frost_protection,
            self.poweron)

    def set_poweron(self, poweron):
        if poweron not in [
            HYSEN_HEAT_POWERON_OFF, 
            HYSEN_HEAT_POWERON_ON]:
            raise ValueError(
                'Can\'t set PowerOn (%s) outside device\'s admitted values (%s), (%s).' % ( \
                poweron,
                HYSEN_HEAT_POWERON_OFF,
                HYSEN_HEAT_POWERON_ON))
        self.get_device_status()
        self.set_options(
            self.external_limit_temp,
            self.hysteresis, 
            self.max_temp,
            self.min_temp, 
            self.calibration, 
            self.frost_protection,
            poweron)

    # set time
    # 0x01,0x10,0x00,0x08,0x00,0x02,0x04, hh, mm, ss, wd
    # hh = Time hour past midnight
    # mm = Time minute past hour
    # ss = Time second past minute
    # wd = Weekday 0x01 = Monday, 0x02 = Tuesday, ..., 0x06 = Saturday, 0x07 = Sunday
    # confirmation response:
    # payload 0x01,0x10,0x00,0x08,0x00,0x02
    def set_time(self, clock_hour, clock_minute, clock_second, clock_weekday):
        if (clock_weekday < 1) or (clock_weekday > 7):
            raise ValueError(
                'Weekday (%s) has to be between 1 (Monday) and 7 (Saturday).' % ( \
                clock_weekday))
        if (clock_hour < 0) or (clock_hour > 23):
            raise ValueError(
                'Hour (%s) has to be between 0 and 23.' % ( \
                clock_hour))
        if (clock_minute < 0) or (clock_minute > 59):
            raise ValueError(
                'Minute (%s) has to be between 0 and 59.' % ( \
                clock_minute))
        if (clock_second < 0) or (clock_second > 59):
            raise ValueError(
                'Second (%s) has to be between 0 and 59.' % ( \
                clock_second))
        _request = bytearray([0x01, 0x10, 0x00, 0x08, 0x00, 0x02, 0x04])
        _request.append(clock_hour)
        _request.append(clock_minute)
        _request.append(clock_second)
        _request.append(clock_weekday)
        self.send_request(_request)

    # set daily schedule
    # 0x01, 0x10, 0x00, 0x0A, 0x00, 0x0C, 0x18, P1h, P1m, P1t, P2h, P2m, P2t, P3h, P3m, P3t, 
    # P4h, P4m, P4t, P5h, P5m, P5t, P6h, P6m, P6t, weP1h, weP1m, weP1t, weP6h, weP6m, weP6t
    # P1h = Period1 hour
    # P1m = Period1 minute
    # P1t = Period1 temperature
    # P2h = Period1 hour
    # P2m = Period1 minute
    # P2t = Period1 temperature
    # P3h = Period1 hour
    # P3m = Period1 minute
    # P3t = Period1 temperature
    # P4h = Period1 hour
    # P4m = Period1 minute
    # P4t = Period1 temperature
    # P5h = Period1 hour
    # P5m = Period1 minute
    # P5t = Period1 temperature
    # P6h = Period1 hour
    # P6m = Period1 minute
    # P6t = Period1 temperature
    # confirmation response:
    # payload 0x01, 0x10, 0x00, 0x0A, 0x00, 0x0C
    def set_daily_schedule(self, period1_hour, period1_min, period2_hour, period2_min, period3_hour, period3_min, period4_hour, period4_min, period5_hour, period5_min, period6_hour, period6_min, we_period1_hour, we_period1_min, we_period6_hour, we_period6_min, period1_temp, period2_temp, period3_temp, period4_temp, period5_temp, period6_temp, we_period1_temp, we_period6_temp):
        _request = bytearray([0x01, 0x10, 0x00, 0x0A, 0x00, 0x0C, 0x18])
        _request.append(period1_hour)
        _request.append(period1_min)
        _request.append(period2_hour)
        _request.append(period2_min)
        _request.append(period3_hour)
        _request.append(period3_min)
        _request.append(period4_hour)
        _request.append(period4_min)
        _request.append(period5_hour)
        _request.append(period5_min)
        _request.append(period6_hour)
        _request.append(period6_min)
        _request.append(we_period1_hour)
        _request.append(we_period1_min)
        _request.append(we_period6_hour)
        _request.append(we_period6_min)
        _request.append(int(period1_temp * 2))
        _request.append(int(period2_temp * 2))
        _request.append(int(period3_temp * 2))
        _request.append(int(period4_temp * 2))
        _request.append(int(period5_temp * 2))
        _request.append(int(period6_temp * 2))
        _request.append(int(we_period1_temp * 2))
        _request.append(int(we_period6_temp * 2))
        self.send_request(_request)

    def set_period1(self, period1_hour = None, period1_min = None, period1_temp = None):
        self.get_device_status()
        if (period1_hour == None):
            period1_hour = self.period1_hour
        if (period1_min == None):
            period1_min = self.period1_min
        if (period1_temp == None):
            period1_temp = self.period1_temp
        if (period1_hour < 0) or (period1_hour > 23):
            raise ValueError(
                'period1_hour (%s) has to be between 0 and 23.' % ( \
                period1_hour))
        if (period1_min < 0) or (period1_min > 59):
            raise ValueError(
                'period1_min (%s) has to be between 0 and 59.' % ( \
                period1_min))
        if (period1_hour > self.period2_hour) or \
            ((period1_hour == self.period2_hour) and (period1_min > self.period2_min)):
            raise ValueError(
                'period1 (%s:%s) has to be before period2 (%s:%s).' % ( \
                period1_hour,
                period1_min,
                self.period2_hour,
                self.period2_min))
        if period1_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                period1_temp,
                self.max_temp))
        if period1_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                period1_temp,
                self.min_temp))
        self.set_daily_schedule(
            period1_hour,
            period1_min, 
            self.period2_hour,
            self.period2_min, 
            self.period3_hour,
            self.period3_min, 
            self.period4_hour,
            self.period4_min, 
            self.period5_hour,
            self.period5_min, 
            self.period6_hour,
            self.period6_min, 
            self.we_period1_hour,
            self.we_period1_min, 
            self.we_period6_hour,
            self.we_period6_min, 
            period1_temp, 
            self.period2_temp,
            self.period3_temp,
            self.period4_temp,
            self.period5_temp,
            self.period6_temp,
            self.we_period1_temp,
            self.we_period6_temp)

    def set_period2(self, period2_hour, period2_min, period2_temp):
        self.get_device_status()
        if (period2_hour == None):
            period2_hour = self.period2_hour
        if (period2_min == None):
            period2_min = self.period2_min
        if (period2_temp == None):
            period2_temp = self.period2_temp
        if (period2_hour < 0) or (period2_hour > 23):
            raise ValueError(
                'period2_hour (%s) has to be between 0 and 23.' % ( \
                period2_hour))
        if (period2_min < 0) or (period2_min > 59):
            raise ValueError(
                'period2_min (%s) has to be between 0 and 59.' % ( \
                period2_min))
        if (period2_hour < self.period1_hour) or \
            ((period2_hour == self.period1_hour) and (period2_min < self.period1_min)):
            raise ValueError(
                'period2 (%s:%s) has to be after period1 (%s:%s).' % ( \
                period2_hour,
                period2_min,
                self.period1_hour,
                self.period1_min))
        if (period2_hour > self.period3_hour) or \
            ((period2_hour == self.period3_hour) and (period2_min > self.period3_min)):
            raise ValueError(
                'period2 (%s:%s) has to be before period3 (%s:%s).' % ( \
                period2_hour,
                period2_min,
                self.period3_hour,
                self.period3_min))
        if period2_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                period2_temp,
                self.max_temp))
        if period2_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                period2_temp,
                self.min_temp))
        self.set_daily_schedule(
            self.period1_hour,
            self.period1_min, 
            period2_hour,
            period2_min, 
            self.period3_hour,
            self.period3_min, 
            self.period4_hour,
            self.period4_min, 
            self.period5_hour,
            self.period5_min, 
            self.period6_hour,
            self.period6_min, 
            self.we_period1_hour,
            self.we_period1_min, 
            self.we_period6_hour,
            self.we_period6_min, 
            self.period1_temp, 
            period2_temp,
            self.period3_temp,
            self.period4_temp,
            self.period5_temp,
            self.period6_temp,
            self.we_period1_temp,
            self.we_period6_temp)

    def set_period3(self, period3_hour, period3_min, period3_temp):
        self.get_device_status()
        if (period3_hour == None):
            period3_hour = self.period3_hour
        if (period3_min == None):
            period3_min = self.period3_min
        if (period3_temp == None):
            period3_temp = self.period3_temp
        if (period3_hour < 0) or (period3_hour > 23):
            raise ValueError(
                'period3_hour (%s) has to be between 0 and 23.' % ( \
                period3_hour))
        if (period3_min < 0) or (period3_min > 59):
            raise ValueError(
                'period3_min (%s) has to be between 0 and 59.' % ( \
                period3_min))
        if (period3_hour < self.period2_hour) or \
            ((period3_hour == self.period2_hour) and (period3_min < self.period2_min)):
            raise ValueError(
                'period3 (%s:%s) has to be after period2 (%s:%s).' % ( \
                period3_hour,
                period3_min,
                self.period2_hour,
                self.period2_min))
        if (period3_hour > self.period4_hour) or \
            ((period3_hour == self.period4_hour) and (period3_min > self.period4_min)):
            raise ValueError(
                'period3 (%s:%s) has to be before period4 (%s:%s).' % ( \
                period3_hour,
                period3_min,
                self.period4_hour,
                self.period4_min))
        if period3_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                period3_temp,
                self.max_temp))
        if period3_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                period3_temp,
                self.min_temp))
        self.set_daily_schedule(
            self.period1_hour,
            self.period1_min, 
            self.period2_hour,
            self.period2_min, 
            period3_hour,
            period3_min, 
            self.period4_hour,
            self.period4_min, 
            self.period5_hour,
            self.period5_min, 
            self.period6_hour,
            self.period6_min, 
            self.we_period1_hour,
            self.we_period1_min, 
            self.we_period6_hour,
            self.we_period6_min, 
            self.period1_temp, 
            self.period2_temp,
            period3_temp,
            self.period4_temp,
            self.period5_temp,
            self.period6_temp,
            self.we_period1_temp,
            self.we_period6_temp)

    def set_period4(self, period4_hour, period4_min, period4_temp):
        self.get_device_status()
        if (period4_hour == None):
            period4_hour = self.period4_hour
        if (period4_min == None):
            period4_min = self.period4_min
        if (period4_temp == None):
            period4_temp = self.period4_temp
        if (period4_hour < 0) or (period4_hour > 23):
            raise ValueError(
                'period4_hour (%s) has to be between 0 and 23.' % ( \
                period4_hour))
        if (period4_min < 0) or (period4_min > 59):
            raise ValueError(
                'period4_min (%s) has to be between 0 and 59.' % ( \
                period4_min))
        if (period4_hour < self.period3_hour) or \
            ((period4_hour == self.period3_hour) and (period4_min < self.period3_min)):
            raise ValueError(
                'period4 (%s:%s) has to be after period3 (%s:%s).' % ( \
                period4_hour,
                period4_min,
                self.period3_hour,
                self.period3_min))
        if (period4_hour > self.period5_hour) or \
            ((period4_hour == self.period5_hour) and (period4_min > self.period5_min)):
            raise ValueError(
                'period4 (%s:%s) has to be before period5 (%s:%s).' % ( \
                period4_hour,
                period4_min,
                self.period5_hour,
                self.period5_min))
        if period4_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                period4_temp,
                self.max_temp))
        if period4_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                period4_temp,
                self.min_temp))
        self.set_daily_schedule(
            self.period1_hour,
            self.period1_min, 
            self.period2_hour,
            self.period2_min, 
            self.period3_hour,
            self.period3_min, 
            period4_hour,
            period4_min, 
            self.period5_hour,
            self.period5_min, 
            self.period6_hour,
            self.period6_min, 
            self.we_period1_hour,
            self.we_period1_min, 
            self.we_period6_hour,
            self.we_period6_min, 
            self.period1_temp, 
            self.period2_temp,
            self.period3_temp,
            period4_temp,
            self.period5_temp,
            self.period6_temp,
            self.we_period1_temp,
            self.we_period6_temp)

    def set_period5(self, period5_hour, period5_min, period5_temp):
        self.get_device_status()
        if (period5_hour == None):
            period5_hour = self.period5_hour
        if (period5_min == None):
            period5_min = self.period5_min
        if (period5_temp == None):
            period5_temp = self.period5_temp
        if (period5_hour < 0) or (period5_hour > 23):
            raise ValueError(
                'period5_hour (%s) has to be between 0 and 23.' % ( \
                period5_hour))
        if (period5_min < 0) or (period5_min > 59):
            raise ValueError(
                'period5_min (%s) has to be between 0 and 59.' % ( \
                period5_min))
        if (period5_hour < self.period4_hour) or \
            ((period5_hour == self.period4_hour) and (period5_min < self.period4_min)):
            raise ValueError(
                'period5 (%s:%s) has to be after period4 (%s:%s).' % ( \
                period5_hour,
                period5_min,
                self.period4_hour,
                self.period4_min))
        if (period5_hour > self.period6_hour) or \
            ((period5_hour == self.period6_hour) and (period5_min > self.period6_min)):
            raise ValueError(
                'period5 (%s:%s) has to be before period6 (%s:%s).' % ( \
                period5_hour,
                period5_min,
                self.period6_hour,
                self.period6_min))
        if period5_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                period5_temp,
                self.max_temp))
        if period5_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                period5_temp,
                self.min_temp))
        self.set_daily_schedule(
            self.period1_hour,
            self.period1_min, 
            self.period2_hour,
            self.period2_min, 
            self.period3_hour,
            self.period3_min, 
            self.period4_hour,
            self.period4_min, 
            period5_hour,
            period5_min, 
            self.period6_hour,
            self.period6_min, 
            self.we_period1_hour,
            self.we_period1_min, 
            self.we_period6_hour,
            self.we_period6_min, 
            self.period1_temp, 
            self.period2_temp,
            self.period3_temp,
            self.period4_temp,
            period5_temp,
            self.period6_temp,
            self.we_period1_temp,
            self.we_period6_temp)

    def set_period6(self, period6_hour, period6_min, period6_temp):
        self.get_device_status()
        if (period6_hour == None):
            period6_hour = self.period6_hour
        if (period6_min == None):
            period6_min = self.period6_min
        if (period6_temp == None):
            period6_temp = self.period6_temp
        if (period6_hour < 0) or (period6_hour > 23):
            raise ValueError(
                'period6_hour (%s) has to be between 0 and 23.' % ( \
                period6_hour))
        if (period6_min < 0) or (period6_min > 59):
            raise ValueError(
                'period6_min (%s) has to be between 0 and 59.' % ( \
                period6_min))
        if (period6_hour < self.period5_hour) or \
            ((period6_hour == self.period5_hour) and (period6_min < self.period5_min)):
            raise ValueError(
                'period6 (%s:%s) has to be after period5 (%s:%s).' % ( \
                period6_hour,
                period6_min,
                self.period5_hour,
                self.period5_min))
        if period6_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                period6_temp,
                self.max_temp))
        if period6_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                period6_temp,
                self.min_temp))
        self.set_daily_schedule(
            self.period1_hour,
            self.period1_min, 
            self.period2_hour,
            self.period2_min, 
            self.period3_hour,
            self.period3_min, 
            self.period4_hour,
            self.period4_min, 
            self.period5_hour,
            self.period5_min, 
            period6_hour,
            period6_min, 
            self.we_period1_hour,
            self.we_period1_min, 
            self.we_period6_hour,
            self.we_period6_min, 
            self.period1_temp, 
            self.period2_temp,
            self.period3_temp,
            self.period4_temp,
            self.period5_temp,
            period6_temp,
            self.we_period1_temp,
            self.we_period6_temp)

    def set_we_period1(self, we_period1_hour, we_period1_min, we_period1_temp):
        self.get_device_status()
        if (we_period1_hour == None):
            we_period1_hour = self.we_period1_hour
        if (we_period1_min == None):
            we_period1_min = self.we_period1_min
        if (we_period1_temp == None):
            we_period1_temp = self.we_period1_temp
        if (we_period1_hour < 0) or (we_period1_hour > 23):
            raise ValueError(
                'we_period1_hour (%s) has to be between 0 and 23.' % ( \
                we_period1_hour))
        if (we_period1_min < 0) or (we_period1_min > 59):
            raise ValueError(
                'we_period1_min (%s) has to be between 0 and 59.' % ( \
                we_period1_min))
        if (we_period1_hour > self.we_period6_hour) or \
            ((we_period1_hour == self.we_period6_hour) and (we_period1_min > self.we_period6_min)):
            raise ValueError(
                'we_period1 (%s:%s) has to be before we_period6 (%s:%s).' % ( \
                we_period1_hour,
                we_period1_min,
                self.we_period6_hour,
                self.we_period6_min))
        if we_period1_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                we_period1_temp,
                self.max_temp))
        if we_period1_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                we_period1_temp,
                self.min_temp))
        self.set_daily_schedule(
            self.period1_hour,
            self.period1_min, 
            self.period2_hour,
            self.period2_min, 
            self.period3_hour,
            self.period3_min, 
            self.period4_hour,
            self.period4_min, 
            self.period5_hour,
            self.period5_min, 
            self.period6_hour,
            self.period6_min, 
            we_period1_hour,
            we_period1_min, 
            self.we_period6_hour,
            self.we_period6_min, 
            self.period1_temp, 
            self.period2_temp,
            self.period3_temp,
            self.period4_temp,
            self.period5_temp,
            self.period6_temp,
            we_period1_temp,
            self.we_period6_temp)

    def set_we_period6(self, we_period6_hour, we_period6_min, we_period6_temp):
        self.get_device_status()
        if (we_period6_hour == None):
            we_period6_hour = self.we_period6_hour
        if (we_period6_min == None):
            we_period6_min = self.we_period6_min
        if (we_period6_temp == None):
            we_period6_temp = self.we_period6_temp
        if (we_period6_hour < 0) or (we_period6_hour > 23):
            raise ValueError(
                'we_period6_hour (%s) has to be between 0 and 23.' % ( \
                we_period6_hour))
        if (we_period6_min < 0) or (we_period6_min > 59):
            raise ValueError(
                'we_period6_min (%s) has to be between 0 and 59.' % ( \
                we_period6_min))
        if (we_period6_hour < self.we_period1_hour) or \
            ((we_period6_hour == self.we_period1_hour) and (we_period6_min < self.we_period1_min)):
            raise ValueError(
                'we_period6 (%s:%s) has to be after we_period1 (%s:%s).' % ( \
                we_period6_hour,
                we_period6_min,
                self.we_period1_hour,
                self.we_period1_min))
        if we_period6_temp > self.max_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) higher than maximum set (%s°).' % ( \
                we_period6_temp,
                self.max_temp))
        if we_period6_temp < self.min_temp:
            raise ValueError(
                'Can\'t set a target temperature (%s°) lower than minimum set (%s°).' % ( \
                we_period6_temp,
                self.min_temp))
        self.set_daily_schedule(
            self.period1_hour,
            self.period1_min, 
            self.period2_hour,
            self.period2_min, 
            self.period3_hour,
            self.period3_min, 
            self.period4_hour,
            self.period4_min, 
            self.period5_hour,
            self.period5_min, 
            self.period6_hour,
            self.period6_min, 
            self.we_period1_hour,
            self.we_period1_min, 
            we_period6_hour,
            we_period6_min, 
            self.period1_temp, 
            self.period2_temp,
            self.period3_temp,
            self.period4_temp,
            self.period5_temp,
            self.period6_temp,
            self.we_period1_temp,
            we_period6_temp)

    # get device status
    # 0x01, 0x03, 0x00, 0x00, 0x00, 0x17
    # response:
    # 0x01, 0x03, 0x2E, 0x0r, 0xavp, Rt, Tt, 0xlm, Sen, Osv, Dif, Svh, Svl, AdjMSB, AdjLSB, Fre, POn, 
    # Unk1, Ext, hh, mm, ss, wd, P1h, P1m, P1t, P2h, P2m, P2t, P3h, P3m, P3t, P4h, P4m, P4t, 
    # P5h, P5m, P5t, P6h, P6m, P6t, weP1h, weP1m, weP1t, weP6h, weP6m, weP6t, Unk2, Unk3
    # r = Remote lock, 0 = Off, 1 = On
    # v = Valve, 0 = Valve off, 1 = Valve on
    # a = Manual over Auto, 0 = Off, 1 = On
    # p = Power State, 0 = Power off, 1 = Power on
    # Rt = Room temperature in degrees Celsius * 2
    # Tt = Target temperature in degrees Celsius * 2
    # l = Weekly schedule, 0x01 = 12345_67, 0x02 = 123456_7, 0x03 = 1234567
    # m = Operation mode, 0x00 = Manual, 0x03 = Auto
    # Sen = sensor, 0x00 = internal, 0x01 = external, 0x02 = internal control with external target
    # Osv = Limit temperature external sensor
    # Dif = Hysteresis
    # Svh = Heating max. temperature
    # Svl = Heating min. temperature
    # Adj = Temperature calibration -5~+5, 0.1 degree Celsius step 
    #       (e.g. -1 = 0xFFF6, -1.4 = 0xFFF2, 0 = 0x0000, +1 = 0x000A, +1.2 = 0x000C, +2 = 0x0014, etc.)
    # Fre = Frost Protection, 0 = On, 1 = Off
    # POn = PowerOn, 0 = Off, 1 = On
    # Unk1 = Unknown, 0x00
    # Ext = External temperature
    # hh = Time hour past midnight
    # mm = Time minute past hour
    # ss = Time second past minute
    # wd = Weekday 0x01 = Monday, 0x01 = Tuesday, ..., 0x06 = Saturday, 0x07 = Sunday
    # P1h = Period1 hour
    # P1m = Period1 minute
    # P1t = Period1 temperature
    # P2h = Period1 hour
    # P2m = Period1 minute
    # P2t = Period1 temperature
    # P3h = Period1 hour
    # P3m = Period1 minute
    # P3t = Period1 temperature
    # P4h = Period1 hour
    # P4m = Period1 minute
    # P4t = Period1 temperature
    # P5h = Period1 hour
    # P5m = Period1 minute
    # P5t = Period1 temperature
    # P6h = Period1 hour
    # P6m = Period1 minute
    # P6t = Period1 temperature
    # weP1h = Weekend Period1 hour
    # weP1m = Weekend Period1 minute
    # weP1t = Weekend Period1 temperature
    # weP6h = Weekend Period6 hour
    # weP6m = Weekend Period6 minute
    # weP6t = Weekend Period6 temperature
    # Unk2 = Unknown, 0x01
    # Unk3 = Unknown, 0x02
    def get_device_status(self):
        _request = bytearray([0x01, 0x03, 0x00, 0x00, 0x00, 0x17])
        _response = self.send_request(_request)
#        _LOGGER.debug("[%s] get_device_status : %s", 
#            self._host, 
#            ' '.join(format(x, '02x') for x in bytearray(_response)))
        self.remote_lock = _response[3] & 0x01
        self.manual_over_auto = (_response[4] >> 6) & 0x01
        self.valve_state =  (_response[4] >> 4) & 0x01
        self.power_state =  _response[4] & 0x01
        self.room_temp = float((_response[5] & 0xFF) / 2.0)
        self.target_temp = float((_response[6] & 0xFF) / 2.0)
        self.operation_mode = _response[7] & 0x0F
        self.schedule = (_response[7] >> 4) & 0x0F
        self.sensor = _response[8]
        self.external_limit_temp = float(_response[9])
        self.hysteresis = _response[10]
        self.max_temp = _response[11]
        self.min_temp = _response[12]
        self.calibration = (_response[13] << 8) + _response[14]
        if self.calibration > 0x7FFF:
            self.calibration = self.calibration - 0x10000
        self.calibration = float(self.calibration / 2.0)
        self.frost_protection = _response[15]
        self.poweron = _response[16]
        self.unknown1 = _response[17]
        self.external_temp = float((_response[18] & 0xFF) / 2.0)
        self.clock_hour = _response[19]
        self.clock_min = _response[20]
        self.clock_sec = _response[21]
        self.clock_weekday = _response[22]
        self.period1_hour = _response[23]
        self.period1_min = _response[24]
        self.period2_hour = _response[25]
        self.period2_min = _response[26]
        self.period3_hour = _response[27]
        self.period3_min = _response[28]
        self.period4_hour = _response[29]
        self.period4_min = _response[30]
        self.period5_hour = _response[31]
        self.period5_min = _response[32]
        self.period6_hour = _response[33]
        self.period6_min = _response[34]
        self.we_period1_hour = _response[35]
        self.we_period1_min = _response[36]
        self.we_period6_hour = _response[37]
        self.we_period6_min = _response[38]
        self.period1_temp = float(_response[39] / 2.0)
        self.period2_temp = float(_response[40] / 2.0)
        self.period3_temp = float(_response[41] / 2.0)
        self.period4_temp = float(_response[42] / 2.0)
        self.period5_temp = float(_response[43] / 2.0)
        self.period6_temp = float(_response[44] / 2.0)
        self.we_period1_temp = float(_response[45] / 2.0)
        self.we_period6_temp = float(_response[46] / 2.0)
        self.unknown2 = _response[47]
        self.unknown3 = _response[48]

