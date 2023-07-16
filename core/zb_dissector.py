#!/usr/bin/env python3
import struct
from typing import Optional

class header_154:
    #Add Payload length instaed of putting the payload
    __slots__ = ('dst16', 'dst64', 'src16', 'src64', 'dst_pan', 'src_pan',
                 'payload_len', 'sequence_number', 'MALFORMED',
                 'frame_control','frame_type', 'security', 'pending', 'ack_request',
                 'pan_id_compression', 'reserved', 'seqno_suppression',
                 'ie_present', 'dst_addr_mode', 'version', 'src_addr_mode', 'packet_len')#'raw_packet')
    
    def __init__(self) -> None:
        self.dst16 = None
        self.dst64 = None
        self.src16 = None
        self.src64 = None
        self.dst_pan = None
        self.src_pan = None
        self.MALFORMED = None
        self.sequence_number = None
        self.payload_len = None
#        self.raw_packet=None
        self.packet_len=None
        
    
    def __dict__(self):
        return {attr: getattr(self, attr) for attr in self.__slots__}
    
    def __len__(self):
        #return len(self.raw_packet)
        return self.packet_len

class ZbFiltering:
    def __init__(self) -> None:
        self.zbdissect = ZbDissector()
    def verify(self,expression:str,header:header_154=None,packet=None):
        if header is None:
            if packet is None: raise ValueError
            wpan= self.zbdissect.packet_dissecting(packet)
            if wpan is None: return None
        else:
            wpan = header
            
        return eval(expression)
            
                
class ZbDissector:
    def __init__(self,fcs_len: int= 2) -> None:
        self.fcs_len=fcs_len
        
    def packet_dissecting(self, packet: bytes, fcs_len: int = None) -> Optional[header_154]:
        wpan = header_154()
        position = 2
        
        if fcs_len is None: fcs_len = self.fcs_len
        
        wpan.packet_len = len(packet)
        #wpan.raw_packet = packet
        
        if len(packet)<2+fcs_len:
            return None
        
        # Parse the 802.15.4 header fields
        
        #Parse fcf
        (wpan.frame_control,) = struct.unpack("<H", packet[:position])
        wpan.frame_type = (wpan.frame_control) & 0b111
        wpan.security = (wpan.frame_control >> 3) & 0b1
        wpan.pending = (wpan.frame_control >> 4) & 0b1
        wpan.ack_request = (wpan.frame_control >> 5) & 0b1
        wpan.pan_id_compression = (wpan.frame_control >> 6) & 0b1
        wpan.reserved = (wpan.frame_control >> 7) & 0b1
        wpan.seqno_suppression = (wpan.frame_control >> 8) & 0b1
        wpan.ie_present = (wpan.frame_control >> 9) & 0b1
        wpan.dst_addr_mode = (wpan.frame_control >> 10) & 0b11
        wpan.version = (wpan.frame_control >> 12) & 0b11
        wpan.src_addr_mode = (wpan.frame_control >> 14) & 0b11
        
        if wpan.dst_addr_mode == 1 or wpan.dst_addr_mode == 1 :
            wpan.MALFORMED = 1
            return wpan
        
        if not wpan.seqno_suppression:
            wpan.sequence_number = packet[position]
            position = position + 1

        if wpan.dst_addr_mode == 2:
            wpan.dst_pan = struct.unpack("<H", packet[position:position+2])[0]
            position = position +2
            
            wpan.dst16 = struct.unpack("<H", packet[position:position+2])[0]
            position = position+2
        elif wpan.dst_addr_mode == 3:
            wpan.dst_pan = struct.unpack("<H", packet[position:position+2])[0]
            position = position +2
            
            wpan.dst64 = struct.unpack("<H", packet[position:position+8])[0]
            position = position + 8
            
        if wpan.src_addr_mode == 2:
            if not wpan.pan_id_compression: 
                wpan.src_pan = struct.unpack("<H", packet[position:position+2])[0]
                position = position +2
            
            wpan.src16=struct.unpack("<H", packet[position:position+2])[0]
            position = position+2
        if wpan.src_addr_mode == 3:
            
            if not wpan.pan_id_compression: 
                wpan.src_pan = struct.unpack("<H", packet[position:position+2])[0]
                position = position +2
                
            wpan.src64=struct.unpack("<H", packet[position:position+8])[0] 
            position = position + 8 
        #This payload len is the packet len - the header len witouth the fcs    
        if position < len(packet)- fcs_len:  
            wpan.payload_len = len(packet[position:-fcs_len]) if fcs_len else len(packet[position:])
        else:
            wpan.payload_len = 0
        
        return wpan
