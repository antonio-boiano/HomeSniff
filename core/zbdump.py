#!/usr/bin/env python3

"""
zbdump.py
"""

import logging
import subprocess
import sys
import time
import asyncio

from typing import Any, Optional, Union
from scapy.all import Dot15d4FCS # type: ignore
import scapy.all as sp
import datetime as dt


_LOGGER = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    
try:
    from killerbee import KillerBee
except ImportError:
    try:
        from ..killerbee import KillerBee
    except ImportError:
        install("git+https://github.com/antonio-boiano/killerbee.git#egg=killerbee")
        from killerbee import KillerBee


try:    
    from killerbee.scapy_extensions import *
except ImportError:
    try:
        from ..killerbee.scapy_extensions import *
    except ImportError:
        install("git+https://github.com/antonio-boiano/killerbee.git#egg=killerbee")
        from killerbee.scapy_extensions import *

try:
    from .zbsocket import *
    from .zbconst import DEFAULT_ZIGBEE_CHANNEL,DEFAULT_QUEUE_BUFFER_SIZE
    from .zb_dissector import ZbDissector,ZbFiltering,header_154
except ImportError:
    from zbsocket import *
    from zbconst import DEFAULT_ZIGBEE_CHANNEL,DEFAULT_QUEUE_BUFFER_SIZE
    from zb_dissector import ZbDissector,ZbFiltering,header_154


class AsyncDump:
    KillerBee = KillerBee

    def __init__(self,channel=11,subghz_page=0,dev_path:Optional[str]=None,hardware:Optional[str]=None,kb:Optional[KillerBee]=None) -> None:
        self.kb: Optional[KillerBee] = kb
        self.channel = 11 if channel is None else channel
        self.subghz_page=subghz_page
        self._queue_list = []
        self._filter_dict = {} 
        self.dev_path=dev_path
        self.hardware=hardware
        self.zbdissect = ZbDissector()
        self.zbfilter = ZbFiltering()
        
        if(self.kb is None):
            try:
                self.kb = KillerBee(device=self.dev_path,hardware=self.hardware)
            except Exception as e:
                _LOGGER.debug("KillerBee cannot find device"+str(e))
                raise
    
    def subscribe (self,queue:asyncio.Queue=None,filter:str=None)->asyncio.Queue: # type: ignore
        """
        Subscribe to the queue to receive packets from the sniffer.
        Args:
            queue (asyncio.Queue, optional): Queue to receive packets. Defaults to None, in this case a new queue is created.
        Returns:
            asyncio.Queue:  Queue to receive packets.
        """
        if not queue:
            queue = asyncio.Queue(DEFAULT_QUEUE_BUFFER_SIZE)
        self._queue_list.append(queue)
        self._filter_dict[queue]=filter
        return queue
    #To Do add filtering capabilities from class zb_filter. In case of filtering return in the queue also the disssected pcket
    #def set_filter(self,queue:asyncio.Queue,filter:str):
        
    
    def unsubscribe (self,queue:asyncio.Queue):
        """ 
        Unsubscribe from the queue to stop receiving packets from the sniffer.

        Args:
            queue (asyncio.Queue): Queue to unsubscribe from.
        """
        
        try:
            self._queue_list.remove(queue)
        except ValueError:
            pass
        
        self._filter_dict.pop(queue,None)
        
    async def start_dump(self,channel:Optional[int]=None,subghz_page:Optional[int]=None,queue=None,async_handler=None):
        
        if subghz_page is not None:
            self.subghz_page=subghz_page
            
        if channel is not None:
            self.channel=channel
        if queue is not None:
            self.subscribe(queue)
            
        if self.kb is not None:
            if not self.kb.is_valid_channel(self.channel, self.subghz_page):
                _LOGGER.debug("Channel and sub_ghz not valid. Using Default channel %d and sub_ghz 0 instead" % DEFAULT_ZIGBEE_CHANNEL)
                self.channel=DEFAULT_ZIGBEE_CHANNEL
                self.subghz_page=0
                
            self.kb.sniffer_on(channel=self.channel,page=self.subghz_page)
            
            if async_handler is None: async_handler = asyncio.create_task
            self.dump_task=async_handler(self.dump_packets())

    
    async def dump_packets(self):
        
        async def handle_queue (packet,queue):
            if self._filter_dict[queue] is not None:
                if not self.zbfilter.verify(self._filter_dict[queue],header=packet["header"]):
                    return None
                else:
                    try:
                        queue.put_nowait(packet)
                    except asyncio.QueueFull:
                        self.unsubscribe(queue)
            else:
                try:
                    queue.put_nowait(packet)
                except asyncio.QueueFull:
                    self.unsubscribe(queue)
                
        async def handle_dissecting(packet:dict[Union[int, str], Any]):
            if packet['bytes'] is None: return None
            packet_header = self.zbdissect.packet_dissecting(packet['bytes'])
            packet['header']=packet_header
            await asyncio.gather(*[handle_queue(packet,queue) for queue in self._queue_list])
            
        if self.kb :
            while True:
                await asyncio.sleep(0)
                packet: Optional[dict[Union[int, str], Any]] = self.kb.pnext()
                if packet is None or not self._queue_list:
                    continue
                else:   
                    await asyncio.create_task(handle_dissecting(packet))
                    
                    
    async def read_pcap(self,file_path,queue:asyncio.Queue=None): # type: ignore
        if not os.path.exists(file_path): return None, None
        if queue is None: queue =  asyncio.Queue(DEFAULT_QUEUE_BUFFER_SIZE)
        
        async def actual_pcap_read(self,file_path,queue:asyncio.Queue):
            pcap = sp.PcapReader(file_path)
            for p in pcap:
                packet = {"bytes":None,"datetime":None,"dbm":None}
                packet["bytes"]= sp.raw(p) # type: ignore
                packet["datetime"]=dt.datetime(1970, 1, 1) + dt.timedelta(seconds=float(p.time)) # type: ignore
                await queue.put(packet)
        
        return queue , asyncio.create_task(actual_pcap_read(self,file_path,queue))
        
    
    async def get_dev_info(self):
        if self.kb:
            return self.kb.get_dev_info()
    
    def get_frequency(self):
        if self.kb is not None:
            freq = self.kb.frequency(self.channel, self.subghz_page) / 1000.0
            return freq
        else:
            return None


    def shutdown(self):
        for k in  self._queue_list: self.unsubscribe(k)
        if self.kb is not None:
            self.kb.sniffer_off()
            self.kb.close()
        if self.dump_task:
            if not self.dump_task.cancelled(): self.dump_task.cancel()
                    
        
class SockZbDump:
    def __init__(
        self,
        channel,
        pcapfile = None,
        dev_path = None,
        dev_name = None,
        ppi=0,
        subghz_page=0,
        pan_id_hex=None,
        count=-1,
        timeout=-1
    ) -> None:
        
        self.packetcount: int = 0
        self.kb: Optional[KillerBee] = None
        self.pcap_dumper: Optional[PcapDumper] = None
        self.usok: Optional[Usocket] = None
        self.unbuffered: Optional[Any] = None
        
        self.channel = channel
        self.pcapfile = pcapfile
        self.devstring = dev_path
        self.device = dev_name
        self.ppi = ppi
        self.subghz_page = subghz_page
        self.pan_id_hex = pan_id_hex
        self.count = count
        self.timeout=timeout
        
        
        

    def close(self) -> None:
        if self.kb is not None:
            self.kb.sniffer_off()
            self.kb.close()

        if self.pcap_dumper is not None:
            self.pcap_dumper.close()

    def dump_packets(self):
        pan = None
        if self.pan_id_hex:
            panid: Optional[int] = int(self.pan_id_hex, 16)
        else:
            panid = None
        if self.kb is not None:
            rf_freq_mhz = self.kb.frequency(self.channel, self.subghz_page) / 1000.0
        else:
            rf_freq_mhz = 0.0

        _LOGGER.debug(
            "zbdump: listening on '{}', channel {}, page {} ({} MHz), link-type DLT_IEEE802_15_4, capture size 127 bytes".format(
                self.devstring, self.channel, self.subghz_page, rf_freq_mhz
            )
        )


        timeout_start = time.time()

        while (time.time() < timeout_start + self.timeout) or (self.count != self.packetcount):
            if self.kb is not None:
                packet: Optional[dict[Union[int, str], Any]] = self.kb.pnext()
            else:
                packet = None

            if packet is None:
                continue

            if panid is not None:
                pan, layer = kbgetpanid(Dot15d4FCS(packet["bytes"]))
                
            

            if panid is None or panid == pan:
                self.packetcount += 1
                if self.pcap_dumper is not None:
                    self.pcap_dumper.pcap_dump(
                        packet["bytes"], ant_dbm=packet["dbm"], freq_mhz=rf_freq_mhz
                    )
            if self.usok is not None:        
                self.usok.send_data_dstream(pickle.dumps(packet))

    
    def capture(self):

        if self.pcapfile is not None and self.pcapfile is not None:
            self.pcap_dumper = PcapDumper(DLT_IEEE802_15_4, self.pcapfile, ppi=self.ppi) # type: ignore

        if self.devstring is None:
            _LOGGER.debug(
                "Autodetection features will be deprecated - please include interface string (e.g. -i /dev/ttyUSB0)"
            )
        if self.device is None:
            _LOGGER.debug(
                "Autodetection features will be deprecated - please include device string (e.g. -d apimote)"
            )

        self.kb = KillerBee(device=self.devstring, hardware=self.device)        

        if not self.kb.is_valid_channel(self.channel, self.subghz_page):
            _LOGGER.error(
                "ERROR: Must specify a valid IEEE 802.15.4 channel for the selected device."
            )
            self.kb.close()

        self.kb.set_channel(self.channel, self.subghz_page)
        self.kb.sniffer_on()


        self.usok = Usocket()
        try:
            self.usok.ustream_start()
        except:
            self.usok.close()
            raise
        
        
        self.dump_packets()

        self.kb.sniffer_off()
        self.kb.close()
        self.usok.close()
        if self.pcap_dumper is not None:
            self.pcap_dumper.close()

        _LOGGER.debug(f"{self.packetcount} packets captured")       
