"""Constants for the 154_sniffer integration."""

SOCKET_PATH = "/tmp/socket_test.s"
CLOSE_CLIENT_CMD = b'end'
CLOSE_CLIENT_TIMEOUT = 3

DEFAULT_ZIGBEE_CHANNEL = 11


DEFAULT_QUEUE_BUFFER_SIZE = 5000 # Reduce this value to decrease the message queue
QUEUE_LASTING_TIME = 0.1


PCAP_FILE_PATH = "pcap"
FEAT_FILE_PATH = "features"

PCAP_FILE_EXTENSION = ".pcap"
FEAT_FILE_EXTENSION = ".csv"

SIX_LWP_VALUE = '6P'
ZB_VALUE = 'ZB'

DEFAULT_ZB_NTWK_SEC_LEVEL = 0x05 # AES-128 Encryption, 32-bit Integrity Protection

DEC_PLACES_LENGTH = 1
DEC_PLACES_TIME = 7
