#!/usr/bin/env python3

# Import necessary libraries and modules
import logging
from typing import Union
from dataclasses import dataclass
import asyncio
import datetime as dt
import csv
import os
import math
import numpy as np
import pandas as pd
from welford import Welford
try:
  from .zb_dissector import *
except:
  from zb_dissector import *



# Import various classes and modules from the Scapy library
# Scapy is a powerful library for analyzing and manipulating wireless communications
from scapy.all import (conf, 
                       Raw,
                       Dot15d4FCS,
                       Dot15d4, 
                       ZigbeeNWK,
                       ZigbeeNWKCommandPayload,
                       ZigbeeSecurityHeader,
                       ZigbeeAppDataPayload,
                       ZigbeeAppCommandPayload,
                       ZigBeeBeacon,
                       ZigbeeNWKStub,
                       ZigbeeAppDataPayloadStub,
                       ZigbeeDeviceProfile,
                       ZigbeeClusterLibrary,
                       LoWPANUncompressedIPv6,
                       LoWPANMesh,
                       LoWPAN_HC2_UDP,
                       LoWPAN_HC1,
                       LoWPANFragmentationFirst,
                       LoWPANFragmentationSubsequent,
                       LoWPANBroadcast,
                       LoWPAN_IPHC,
                       LoWPAN_NHC_Hdr,
                       LoWPAN_NHC_UDP,
                       LoWPAN_NHC_IPv6Ext,
                       LoWPAN_NHC,
                       SixLoWPAN_ESC,
                       SixLoWPAN                  
                       )
from scapy.packet import Gen

# Import constants from the zbconst module
# These constants are used to specify the location of PCAP and feature files
# And the default network security level for Zigbee

#ToDo define output file names in .zbconst

try:
  from .zbconst import (PCAP_FILE_PATH,
                        PCAP_FILE_EXTENSION,
                        FEAT_FILE_PATH,
                        FEAT_FILE_EXTENSION,
                        DEFAULT_ZB_NTWK_SEC_LEVEL,
                        DEC_PLACES_LENGTH,
                        DEC_PLACES_TIME,)
except ImportError:
  from zbconst import (PCAP_FILE_PATH,
                        PCAP_FILE_EXTENSION,
                        FEAT_FILE_PATH,
                        FEAT_FILE_EXTENSION,
                        DEFAULT_ZB_NTWK_SEC_LEVEL,
                        DEC_PLACES_LENGTH,
                        DEC_PLACES_TIME,)
# Create a logger object to log messages
_LOGGER = logging.getLogger(__name__)

# Import killerbee library manually
try:
    from killerbee import *
except ImportError:
    try:
        from ..killerbee import *
    except ImportError as e:
        raise e
        
@dataclass
class FeaturesConfig:
    """
    Initialize the class with default values for the features
    """
    # Topology map feature
    topology_map:bool = False
    # Time window feature (in seconds)
    time_window:int = 5

    # If Time Window == 0 (real time data extraction)
    # Timestamp feature
    timestamp:bool = True
    # Relative time feature
    relative_time:bool = True
    # Length feature
    length:bool = True
    # Payload data length feature
    payload_data_length:bool = True
    # RSSI feature
    dbm:bool = True
    # Formatting type feature
    # 0 for raw packet type and 1 for direction based type
    formatting_type:bool = False
    
    # Src feature (valid if formatting_type == 0)
    src:bool = True
    # Dest feature (valid if formatting_type == 0)
    dest:bool = True
    
    # Incoming feature (valid if formatting_type == 1 or in case time_window >0)
    incoming:bool =True
    # Outgoing feature (valid if formatting_type == 1 or in case time_window >0)
    outgoing:bool = True
    # Incoming + Outgoing stats (valid if time_window >0)
    total:bool= True
    
    # If Time Window >0
    # Mean inter-arrival time feature
    mean_inter_arrival_time:int = 7
    # Mean size feature
    mean_size:int = 7
    # Mean payload size feature
    mean_payload_size:int = 7
    # Standard deviation of inter-arrival time feature
    std_inter_arrival_time:int = 7
    # Standard deviation of size feature
    std_size:int = 7
    # Standard deviation of payload size feature
    std_payload_size:int = 7
    # Mean absolute deviation of inter-arrival time feature
    mad_inter_arrival_time:int = 7
    # Mean absolute deviation of size feature
    mad_size:int = 7
    # Mean absolute deviation of payload size feature
    mad_payload_size:int = 7
    # Count the number of packets received in a time window
    count_packets:int = 7
    
    # Filtering string
    filter_string:str = None
    
    # CSV separator feature
    csv_separator:str = ','

    pcap_file_path:str = None
    #ToDo:
    #Uplink,Downlink, filter 0x0000 adr, add filter string capabilities
    
    
@dataclass
class FilesConfig:
    """
    File configurations dataclass
    """
    # Maximum time (in seconds) for PCAP file
    pcap_max_time:int = 0
    # Maximum size (in bytes) for PCAP file
    pcap_max_size:int = 0
    # Maximum number of packets for PCAP file
    pcap_max_packets:int = 0
    # Maximum number of files to be created
    pcap_max_files:int = 0
    # PCAP file split size (in bytes)
    pcap_split_size:int = 0
    # Filtering string
    filter_string:str = None


class zbAnalyzePackets:
  zigbee_packet_type = [
                       ZigbeeNWK,
                       ZigbeeNWKCommandPayload,
                       ZigbeeSecurityHeader,
                       ZigbeeAppDataPayload,
                       ZigbeeAppCommandPayload,
                       ZigBeeBeacon,
                       ZigbeeNWKStub,
                       ZigbeeAppDataPayloadStub,
                       ZigbeeDeviceProfile,
                       ZigbeeClusterLibrary]
  lowpan_packet_type = [                       
                       LoWPANUncompressedIPv6,
                       LoWPANMesh,
                       LoWPAN_HC2_UDP,
                       LoWPAN_HC1,
                       LoWPANFragmentationFirst,
                       LoWPANFragmentationSubsequent,
                       LoWPANBroadcast,
                       LoWPAN_IPHC,
                       LoWPAN_NHC_Hdr,
                       LoWPAN_NHC_UDP,
                       LoWPAN_NHC_IPv6Ext,
                       LoWPAN_NHC,
                       SixLoWPAN_ESC,
                       SixLoWPAN]

  def __init__ (self,feat_cfg:FeaturesConfig):
    self.feat_cfg :FeaturesConfig  = feat_cfg
    self.packet_conv_time = None
    self.first_packet_time = None
    self.packet_pds=pd.DataFrame()
    self.packet_list=list()
    
    
    self.extract_data_memory = None
    self.store_features_memory = {}
    self.iterations = 0
    
    
  def reset_welford(self):
    self.extract_data_memory = None
    self.store_features_memory = {}
    self.iterations = 0
  
  def get_welford(self):
    
    if self.extract_data_memory is not None:
      return self.extract_data_memory
    
    if len(self.store_features_memory) > 0:
      self.extract_data_memory={"features":[],"topology":[]}
      self.extract_data_memory['features']= self.convert_features_to_dict(self.store_features_memory)
      return self.extract_data_memory
    
    return None

    
    
  def get_param(self,packet: Gen,subject):
    try:
      get_result = getattr(packet[Dot15d4FCS], subject)
      return get_result
    except:
      return np.nan
  
  def convert_packet(self,raw_pck):
    packet_type = ""
    conf.dot15d4_protocol='zigbee'
    packet=Dot15d4FCS(raw_pck)
    if packet is None:
      _LOGGER.warning("Could not parse the packet passed as input")
      return None, None
    
    if Raw in packet:
      _LOGGER.warning("Malformed Packet or invalid Dot15d4Packet or unknown underly protocol used")
      return None, None
    if Dot15d4 in packet:
      packet_type = '154'          
      
    if ((getattr(packet[Dot15d4FCS], 'fcf_srcaddrmode')==3) and (getattr(packet[Dot15d4FCS], 'fcf_frametype')==1)):
      conf.dot15d4_protocol='sixlowpan'
      packet=Dot15d4FCS(raw_pck)
      if any(item in packet for item in zbAnalyzePackets.lowpan_packet_type): packet_type = '6P' 
    else:
      #if ZigbeeSecurityHeader in packet and (packet.flags >> 1) & 1 and not packet.fcf_framever and not packet.nwk_seclevel : #(packet.flags >> 1) & 1 -> The bit representing the FCF Security field in ZbeeNW Header
      #  packet.nwk_seclevel = DEFAULT_ZB_NTWK_SEC_LEVEL
      #  packet=Dot15d4FCS(bytes(packet))
      #  packet_type = 'ZB'
      #  return packet, packet_type
  
      if any(item in packet for item in zbAnalyzePackets.zigbee_packet_type): packet_type = 'ZB'       
      
    return packet, packet_type
  
  def extract_info_header(self,packet:header_154,time,dbm,topology:bool):
    def get_obj(obj):
      if obj is None:
        return np.nan
      else:
        return obj
      
    pck_frame = {} #pd.DataFrame()
    
    if packet is None or time is None:
      return None

    pck_type=''

    
    if self.first_packet_time is None:
      self.first_packet_time = time
      
    if self.packet_conv_time is None:
      self.packet_conv_time = time
    
    
    pck_frame['time']=[(time-self.packet_conv_time).total_seconds()] if type(pck_frame)== pd.DataFrame else (time-self.packet_conv_time).total_seconds()

    pck_frame['dbm']= dbm if (dbm) else np.nan
    
    #TODO this might not be true we might have always the src pan
    if packet.dst_pan is not None:
      pck_frame['pan_id']=get_obj(packet.dst_pan)
    else:
      pck_frame['pan_id']=get_obj(packet.src_pan)
        
    pck_frame['src_addr']=get_obj(packet.src16)
    
    pck_frame['dest_addr']=get_obj(packet.dst16)
    
    #ToDo Do packet type in a clever way, suggest what type of packt was exchanged (ack, beacon etc)  
    pck_frame['protocol']=pck_type if (pck_type) else np.nan
    
    pck_frame['length']=get_obj(packet.packet_len)
    
    #This payload len is the packet len - the header len witouth the fcs    
    pck_frame['payload_data_length']=get_obj(packet.payload_len)
    
    
    # if topology:
    #   pck_frame['ext_dst']=self.get_param(packet,'ext_dst')
      
    #   pck_frame['ext_dst']=pck_frame['src_addr'] if (not pck_frame['ext_dst'] and (getattr(packet[Dot15d4FCS], 'fcf_srcaddrmode')==3)) else np.nan
        
    #   pck_frame['ext_src']=self.get_param(packet,'ext_src')
      
    #   pck_frame['ext_dst']=pck_frame['dest_addr'] if (not pck_frame['ext_dst'] and (getattr(packet[Dot15d4FCS], 'fcf_srcaddrmode')==3)) else np.nan
      
    #   pck_frame['extended_pan_id']=self.get_param(packet,'extended_pan_id')
    
    return pck_frame
  
  def extract_info_scapy(self,raw_pck:Union[bytes, bytearray],time,dbm,topology:bool):
    pck_frame = {} #pd.DataFrame()
    
    if raw_pck is None or time is None:
      return None
    
    packet, pck_type =self.convert_packet(raw_pck)
    
    if packet is None or time is None:
      return None
    
    if self.first_packet_time is None:
      self.first_packet_time = time
      
    if self.packet_conv_time is None:
      self.packet_conv_time = time
    
    
    pck_frame['time']=[(time-self.packet_conv_time).total_seconds()] if type(pck_frame)== pd.DataFrame else (time-self.packet_conv_time).total_seconds()

    pck_frame['dbm']= dbm if (dbm) else np.nan
      
    if (self.get_param(packet,'dest_panid')  is not np.nan):
      pck_frame['pan_id']=self.get_param(packet,'dest_panid')
    else:
      pck_frame['pan_id']=self.get_param(packet,'src_panid')
        
    pck_frame['src_addr']=self.get_param(packet,'src_addr')
      
    pck_frame['dest_addr']=self.get_param(packet,'dest_addr')
    #ToDo Do packet type in a clever way, suggest what type of packt was exchanged (ack, beacon etc)  
    pck_frame['protocol']=pck_type if (pck_type) else np.nan
    
    pck_frame['length']=len(packet)
    
    try:
      
      tmp_var = len(packet.data)
      if ZigbeeSecurityHeader in packet and (packet.flags >> 1) & 1 and not packet.fcf_framever and not packet.nwk_seclevel : #(packet.flags >> 1) & 1 -> The bit representing the FCF Security field in ZbeeNW Header
        pck_frame['payload_data_length']=len(packet.data)-4 if len(packet.data)>4 else len(packet.data) #Remove the MIC length which by default is 32 bit
      else:
        pck_frame['payload_data_length']=len(packet.data)
    except:
      pck_frame['payload_data_length']=np.nan
    
    if topology:
      pck_frame['ext_dst']=self.get_param(packet,'ext_dst')
      
      pck_frame['ext_dst']=pck_frame['src_addr'] if (not pck_frame['ext_dst'] and (getattr(packet[Dot15d4FCS], 'fcf_srcaddrmode')==3)) else np.nan
        
      pck_frame['ext_src']=self.get_param(packet,'ext_src')
      
      pck_frame['ext_dst']=pck_frame['dest_addr'] if (not pck_frame['ext_dst'] and (getattr(packet[Dot15d4FCS], 'fcf_srcaddrmode')==3)) else np.nan
      
      pck_frame['extended_pan_id']=self.get_param(packet,'extended_pan_id')
    
    return pck_frame

  async def real_time_dict_df(self,df,is_relative:bool=1):
    if df is None:
      return None
    col_name=list()
    
    if self.feat_cfg.timestamp: col_name.append('time')
    if self.feat_cfg.dbm: col_name.append('dbm')
    if self.feat_cfg.length: col_name.append('length')
    if self.feat_cfg.payload_data_length: col_name.append('payload_data_length')
    if self.feat_cfg.src: col_name.append('src_addr')
    if self.feat_cfg.dest: col_name.append('dest_addr')
    
    out_df=pd.DataFrame(df[col_name])   
    out_df['time']=out_df['time'].apply(lambda x: x if is_relative else self.packet_conv_time+dt.timedelta(seconds=x))
    
    return out_df

  async def real_time_dict(self,pck_dict,is_relative:bool=1):
    feature_dict = list()
    feature_dict_tmp={}
    
    if pck_dict is None:
      return None

    if self.feat_cfg.timestamp: 
      feature_dict_tmp['time'] = pck_dict['time'] if is_relative else self.packet_conv_time+dt.timedelta(seconds=pck_dict['time'])
    if self.feat_cfg.dbm: feature_dict_tmp['dbm']=pck_dict['dbm']
    if self.feat_cfg.length: feature_dict_tmp['length']=pck_dict['length']
    if self.feat_cfg.payload_data_length: feature_dict_tmp['payload_data_length']=pck_dict['payload_data_length']
    if self.feat_cfg.src: feature_dict_tmp['src_addr'] = pck_dict['src_addr']
    if self.feat_cfg.dest: feature_dict_tmp['dest_addr'] = pck_dict['dest_addr']
    feature_dict.append(feature_dict_tmp)
    return feature_dict

  async def real_time_dict_direction(self,pck_dict,is_relative:bool=1):
    feature_dict = list()
    feature_dict_tmp={}
    
    if pck_dict is None:
      return None
    
    feature_dict_tmp['time'] = pck_dict['time'] if is_relative else self.packet_conv_time+dt.timedelta(seconds=pck_dict['time'])
    if self.feat_cfg.dbm: feature_dict_tmp['dbm']=pck_dict['dbm']
    if self.feat_cfg.length or self.feat_cfg.time_window>0 :feature_dict_tmp['length']=pck_dict['length']
    if (self.feat_cfg.payload_data_length or self.feat_cfg.time_window>0) and 'payload_data_length' in pck_dict:feature_dict_tmp['payload_data_length']=pck_dict['payload_data_length']
    
    if self.feat_cfg.incoming or self.feat_cfg.time_window>0:
      feature_dict_tmp['addr'] = pck_dict['dest_addr']
      feature_dict_tmp['direction']=1 #1 is incoming
      feature_dict.append(feature_dict_tmp.copy())
      
    if self.feat_cfg.outgoing or self.feat_cfg.time_window>0:
      feature_dict_tmp['addr'] = pck_dict['src_addr']
      feature_dict_tmp['direction']=0 #0 is outgoing
      feature_dict.append(feature_dict_tmp)
    
    return feature_dict

  async def real_time_dict_direction_pd(self,df,is_relative:bool=1):
    if df is None:
      return None
    df=pd.DataFrame([df])
    col_name=list()
    
    out_df = None
    dest_df = None
    
    if self.feat_cfg.timestamp: col_name.append('time')
    if self.feat_cfg.dbm: col_name.append('dbm')
    if self.feat_cfg.length: col_name.append('length')
    if self.feat_cfg.payload_data_length: col_name.append('payload_data_length')
    if self.feat_cfg.src: col_name.append('src_addr')
    
    out_df=df[col_name]

    if self.feat_cfg.src: out_df=out_df.assign(direction=1)
    out_df=out_df.rename(columns={'src_addr':'addr'})
  
    if self.feat_cfg.dest:
      if 'src_addr' in col_name: col_name.remove('src_addr')
      col_name.append('dest_addr')
      dest_df=df[col_name]
      dest_df=dest_df.rename(columns={'dest_addr':'addr'})
      dest_df=dest_df.assign(direction=0)
      
    
    out_df=pd.concat([out_df,dest_df],ignore_index=True)
    out_df['time']=out_df['time'].apply(lambda x: x if is_relative else self.packet_conv_time+dt.timedelta(seconds=x))
    
    return out_df

  async def topology_map_df(self,df):
    if df is None:
      return None
    
    src=['pan_id','extended_pan_id','protocol','src_addr','ext_src']
    dst=['pan_id','extended_pan_id','protocol','dest_addr','ext_dst']
    
    src_df=df[src]
    src_df=src_df.rename(columns={'src_addr':'addr', 'ext_src':'mac'})
    dest_df=df[dst]
    dest_df=dest_df.rename(columns={'dest_addr':'addr', 'ext_dst':'mac'})
    
    out_df=pd.concat([src_df,dest_df],ignore_index=True)

    return out_df

  async def topology_map(self,pck_dict):
    topology_dict= list()
    topology_dict_tmp={}
    
    topology_dict_tmp['pan_id']=pck_dict['pan_id']
    topology_dict_tmp['extended_pan_id']=pck_dict['extended_pan_id']
    topology_dict_tmp['protocol']=pck_dict['protocol']
    
    if pck_dict['src_addr']:
      topology_dict_tmp['addr']=pck_dict['src_addr']
      topology_dict_tmp['mac']=pck_dict['ext_src']
      topology_dict.append(topology_dict_tmp.copy())
      
    if pck_dict['dest_addr']:
      topology_dict_tmp['addr']=pck_dict['dest_addr']
      topology_dict_tmp['mac']=pck_dict['ext_dst']
      topology_dict.append(topology_dict_tmp)
    
    return topology_dict

  async def windowed_feat_df(self,df:pd.DataFrame,time_window:int):
    def get_bit(num, x):
      mask = 1 << x
      return (num & mask) != 0
    
    async def compute_feat(self,name,group,time_window):
      df_group_tmp = pd.DataFrame(group)
      tmp_df=pd.DataFrame()
      
      tmp_df['addr']=[name]
      tmp_df['time']=[((self.packet_conv_time-self.first_packet_time).total_seconds()+time_window)] if self.feat_cfg.relative_time else [self.packet_conv_time]
      
      df_group=df_group_tmp
      if not df_group.empty:
        if get_bit(self.feat_cfg.mean_size,2): tmp_df['tot_mean_length'] = round(np.mean(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_size,2): tmp_df['tot_std_length'] = round(np.std(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_size,2): tmp_df['tot_mad_length'] = round(np.median(np.absolute(df_group['length'] - np.median(df_group['length']))),DEC_PLACES_LENGTH)

        if get_bit(self.feat_cfg.mean_payload_size ,2): tmp_df['tot_mean_payload_data_length'] = round(np.mean(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_payload_size,2): tmp_df['tot_std_payload_data_length'] = round(np.std(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_payload_size,2): tmp_df['tot_mad_payload_data_length'] = round(np.median(np.absolute(df_group['payload_data_length'] - np.median(df_group['payload_data_length']))),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.count_packets,2): tmp_df['tot_count'] = round(df_group.size,DEC_PLACES_LENGTH)
        
        
        tim_df=df_group['time'].diff()
        if tim_df.any():
          if get_bit(self.feat_cfg.mean_inter_arrival_time ,2): tmp_df['tot_mean_inter_time'] = round(np.mean(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.std_inter_arrival_time,2): tmp_df['tot_std_inter_time'] = round(np.std(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.mad_inter_arrival_time,2): tmp_df['tot_mad_inter_time'] = round(np.median(np.absolute(tim_df - np.median(tim_df))),DEC_PLACES_TIME)
      
      df_group= df_group_tmp.query("variable == 'dest_addr'")
      if not df_group.empty:
        if get_bit(self.feat_cfg.mean_size,0): tmp_df['in_mean_length'] = round(np.mean(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_size,0): tmp_df['in_std_length'] = round(np.std(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_size,0): tmp_df['in_mad_length'] = round(np.median(np.absolute(df_group['length'] - np.median(df_group['length']))),DEC_PLACES_LENGTH)

        if get_bit(self.feat_cfg.mean_payload_size ,0): tmp_df['in_mean_payload_data_length'] = round(np.mean(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_payload_size,0): tmp_df['in_std_payload_data_length'] = round(np.std(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_payload_size,0): tmp_df['in_mad_payload_data_length'] = round(np.median(np.absolute(df_group['payload_data_length'] - np.median(df_group['payload_data_length']))),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.count_packets,0): tmp_df['in_count'] = round(df_group.size,DEC_PLACES_LENGTH)        
        tim_df=df_group['time'].diff()
        if tim_df.any():
          if get_bit(self.feat_cfg.mean_inter_arrival_time ,0): tmp_df['in_mean_inter_time'] = round(np.mean(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.std_inter_arrival_time,0): tmp_df['in_std_inter_time'] = round(np.std(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.mad_inter_arrival_time,0): tmp_df['in_mad_inter_time'] = round(np.median(np.absolute(tim_df - np.median(tim_df))),DEC_PLACES_TIME)
      
      df_group= df_group_tmp.query("variable == 'src_addr'")
      if not df_group.empty:
        if get_bit(self.feat_cfg.mean_size,1): tmp_df['out_mean_length'] = round(np.mean(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_size,1): tmp_df['out_std_length'] = round(np.std(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_size,1): tmp_df['out_mad_length'] = round(np.median(np.absolute(df_group['length'] - np.median(df_group['length']))),DEC_PLACES_LENGTH)

        if get_bit(self.feat_cfg.mean_payload_size ,1): tmp_df['out_mean_payload_data_length'] = round(np.mean(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_payload_size,1): tmp_df['out_std_payload_data_length'] = round(np.std(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_payload_size,1): tmp_df['out_mad_payload_data_length'] = round(np.median(np.absolute(df_group['payload_data_length'] - np.median(df_group['payload_data_length']))),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.count_packets,1): tmp_df['out_count'] = round(df_group.size,DEC_PLACES_LENGTH)
        tim_df=df_group['time'].diff()
        if tim_df.any():
          if get_bit(self.feat_cfg.mean_inter_arrival_time ,1): tmp_df['out_mean_inter_time'] = round(np.mean(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.std_inter_arrival_time,1): tmp_df['out_std_inter_time'] = round(np.std(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.mad_inter_arrival_time,1): tmp_df['out_mad_inter_time'] = round(np.median(np.absolute(tim_df - np.median(tim_df))),DEC_PLACES_TIME)
      return tmp_df
    
    async def feature_extractor(self,time_window_pck,time_window):
      columns_to_melt = ['src_addr','dest_addr']
      id_vars = [col for col in time_window_pck.columns if col not in columns_to_melt]
      df_melted = pd.melt(time_window_pck, id_vars=id_vars, value_vars=columns_to_melt)
      grouped =  df_melted.groupby('value',as_index=False, sort=False)
      feat_val = await asyncio.gather(*[compute_feat(self,name,group,time_window) for name, group in grouped])
      return pd.concat(feat_val,ignore_index=True)


    out=pd.DataFrame()
    if not df.empty:
      self.packet_pds=pd.concat([self.packet_pds,df],ignore_index=True)
    try:
      last_time = self.packet_pds['time'][-1:].item()
    except KeyError:
      return out
      
    if last_time>time_window:
      #packet_list_temp = self.packet_pds.loc[self.packet_pds['time']>time_window]
      time_window_pck=self.packet_pds.query('time <= @time_window and time > 0')
      if not time_window_pck.empty:
        try:
          out= await feature_extractor(self,time_window_pck,time_window)
        except Exception as e:
          raise
      self.packet_pds['time']=self.packet_pds['time'] - time_window
      #packet_list_temp.assign(time = lambda x: x['time'] - time_window)
      
      self.packet_conv_time+=dt.timedelta(seconds=time_window)

      tmp_out=await self.windowed_feat_df(pd.DataFrame(),time_window)
      return pd.concat([out,tmp_out])
    
    return out
  
  async def windowed_feat_dict(self,pck_list:list,time_window:int):
    def get_bit(num, x):
      mask = 1 << x
      return (num & mask) != 0
    
    async def compute_feat(self,name,group,time_window):
      df_group_tmp = pd.DataFrame(group)
      tmp_df=pd.DataFrame()
      
      tmp_df['addr']=[name]
      tmp_df['time']=[((self.packet_conv_time-self.first_packet_time).total_seconds()+time_window)] if self.feat_cfg.relative_time else [self.packet_conv_time]
      
      df_group=df_group_tmp
      if not df_group.empty:
        if get_bit(self.feat_cfg.mean_size,2): tmp_df['tot_mean_length'] = round(np.mean(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_size,2): tmp_df['tot_std_length'] = round(np.std(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_size,2): tmp_df['tot_mad_length'] = round(np.median(np.absolute(df_group['length'] - np.median(df_group['length']))),DEC_PLACES_LENGTH)

        if get_bit(self.feat_cfg.mean_payload_size ,2): tmp_df['tot_mean_payload_data_length'] = round(np.mean(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_payload_size,2): tmp_df['tot_std_payload_data_length'] = round(np.std(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_payload_size,2): tmp_df['tot_mad_payload_data_length'] = round(np.median(np.absolute(df_group['payload_data_length'] - np.median(df_group['payload_data_length']))),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.count_packets,2): tmp_df['tot_count'] = round(df_group.size,DEC_PLACES_LENGTH)
        tim_df_raw=df_group['time'].diff()
        if tim_df_raw.size > 1:
          tim_df=tim_df_raw.tail(-1)
          if get_bit(self.feat_cfg.mean_inter_arrival_time ,2): tmp_df['tot_mean_inter_time'] = round(np.mean(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.std_inter_arrival_time,2): tmp_df['tot_std_inter_time'] = round(np.std(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.mad_inter_arrival_time,2): tmp_df['tot_mad_inter_time'] = round(np.median(np.absolute(tim_df - np.median(tim_df))),DEC_PLACES_TIME)
        
      df_group= df_group_tmp.query("variable == 'dest_addr'")
      if not df_group.empty:
        if get_bit(self.feat_cfg.mean_size,0): tmp_df['in_mean_length'] = round(np.mean(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_size,0): tmp_df['in_std_length'] = round(np.std(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_size,0): tmp_df['in_mad_length'] = round(np.median(np.absolute(df_group['length'] - np.median(df_group['length']))),DEC_PLACES_LENGTH)

        if get_bit(self.feat_cfg.mean_payload_size ,0): tmp_df['in_mean_payload_data_length'] = round(np.mean(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_payload_size,0): tmp_df['in_std_payload_data_length'] = round(np.std(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_payload_size,0): tmp_df['in_mad_payload_data_length'] = round(np.median(np.absolute(df_group['payload_data_length'] - np.median(df_group['payload_data_length']))),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.count_packets,0): tmp_df['in_count'] = round(df_group.size,DEC_PLACES_LENGTH)
        tim_df_raw=df_group['time'].diff()
        if tim_df_raw.size > 1:
          tim_df=tim_df_raw.tail(-1)
          if get_bit(self.feat_cfg.mean_inter_arrival_time ,0): tmp_df['in_mean_inter_time'] = round(np.mean(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.std_inter_arrival_time,0): tmp_df['in_std_inter_time'] = round(np.std(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.mad_inter_arrival_time,0): tmp_df['in_mad_inter_time'] = round(np.median(np.absolute(tim_df - np.median(tim_df))),DEC_PLACES_TIME)
      
      df_group= df_group_tmp.query("variable == 'src_addr'")
      if not df_group.empty:
        if get_bit(self.feat_cfg.mean_size,1): tmp_df['out_mean_length'] = round(np.mean(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_size,1): tmp_df['out_std_length'] = round(np.std(df_group['length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_size,1): tmp_df['out_mad_length'] = round(np.median(np.absolute(df_group['length'] - np.median(df_group['length']))),DEC_PLACES_LENGTH)

        if get_bit(self.feat_cfg.mean_payload_size ,1): tmp_df['out_mean_payload_data_length'] = round(np.mean(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.std_payload_size,1): tmp_df['out_std_payload_data_length'] = round(np.std(df_group['payload_data_length']),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.mad_payload_size,1): tmp_df['out_mad_payload_data_length'] = round(np.median(np.absolute(df_group['payload_data_length'] - np.median(df_group['payload_data_length']))),DEC_PLACES_LENGTH)
        if get_bit(self.feat_cfg.count_packets,1): tmp_df['out_count'] = round(df_group.size,DEC_PLACES_LENGTH)
        tim_df_raw=df_group['time'].diff()
        if tim_df_raw.size > 1:
          tim_df=tim_df_raw.tail(-1)
          if get_bit(self.feat_cfg.mean_inter_arrival_time ,1): tmp_df['out_mean_inter_time'] = round(np.mean(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.std_inter_arrival_time,1): tmp_df['out_std_inter_time'] = round(np.std(tim_df),DEC_PLACES_TIME)
          if get_bit(self.feat_cfg.mad_inter_arrival_time,1): tmp_df['out_mad_inter_time'] = round(np.median(np.absolute(tim_df - np.median(tim_df))),DEC_PLACES_TIME)
      return tmp_df
    
    async def feature_extractor(self,window_pck,time_window):
      
      columns_to_melt = ['src_addr','dest_addr']
      time_window_pck = window_pck.copy()
      time_window_pck.src_addr = time_window_pck.src_addr.fillna(-1)
      time_window_pck.dest_addr = time_window_pck.dest_addr.fillna(-1)
      id_vars = [col for col in time_window_pck.columns if col not in columns_to_melt]
      df_melted = pd.melt(time_window_pck, id_vars=id_vars, value_vars=columns_to_melt)
      grouped =  df_melted.groupby('value',as_index=False, sort=False)
      feat_val = await asyncio.gather(*[compute_feat(self,name,group,time_window) for name, group in grouped])
      return pd.concat(feat_val,ignore_index=True)

    out=pd.DataFrame()
    
    if pck_list is None:
      return out
    
    if pck_list:
      self.packet_list.extend([pck_list])
    try:
      last_time = self.packet_list[-1]['time']
    except KeyError:
      return out
      
    if last_time>time_window:
      #packet_list_temp = self.packet_pds.loc[self.packet_pds['time']>time_window]
      self.packet_pds=pd.DataFrame(self.packet_list)
      time_window_pck=self.packet_pds.query('time <= @time_window and time > 0')
      if not time_window_pck.empty:
        try:
          out= await feature_extractor(self,time_window_pck,time_window)
        except Exception as e:
          #return out
          raise e
        
      self.packet_pds['time']=self.packet_pds['time'] - time_window
      self.packet_list = (self.packet_pds.query('time > 0')
                          .to_dict('records')
                          )
      #packet_list_temp.assign(time = lambda x: x['time'] - time_window)
      
      self.packet_conv_time+=dt.timedelta(seconds=time_window)

      tmp_out = await self.windowed_feat_dict(None,time_window)
      #out.extend(tmp_out)
      return pd.concat([out,tmp_out])
    return out
  
  async def extract_windowed_feat(self,pck_list:list,time_window):
    def get_bit(num, x):
      mask = 1 << x
      return (num & mask) != 0
    
    def append_feat(pck_dict,globla_dict=None):
      
      """
        Update the input dictionary with features extracted from a packet dictionary.

        Parameters:
            pck_dict (dict): A dictionary representing a packet with keys:
                - 'direction': An integer value indicating the direction of the packet (0 or 1).
                - 'time': A float value indicating the timestamp of the packet.
                - 'length': An integer value indicating the length of the packet.
                - 'payload_data_length': An integer value indicating the length of the payload data of the packet.
            global_dict (dict): A dictionary containing global features. Default is None.

        Returns:
            dict: The updated input dictionary with the following features:
                - 'int_arv_tm_in': A list of float values representing the inter-arrival time of incoming packets.
                - 'length_in': A list of integer values representing the length of incoming packets.
                - 'payload_data_length_in': A list of integer values representing the length of the payload data of incoming packets.
                - 'int_arv_tm_out': A list of float values representing the inter-arrival time of outgoing packets.
                - 'length_out': A list of integer values representing the length of outgoing packets.
                - 'payload_data_length_out': A list of integer values representing the length of the payload data of outgoing packets.
                - 'int_arv_tm_tot': A list of float values representing the total inter-arrival time of packets.
                - 'length_tot': A list of integer values representing the total length of packets.
                - 'payload_data_length_tot': A list of integer values representing the total length of the payload data of packets.
      """
      input_dict = {} if globla_dict is None else globla_dict 
      if pck_dict['direction']==1:
        if 'int_arv_tm_in' not in input_dict:
          input_dict['int_arv_tm_in'] = list()
          input_dict['int_arv_tm_in'].append(pck_dict['time'] )
        else:
          input_dict['int_arv_tm_in'][-1] = pck_dict['time'] -input_dict['int_arv_tm_in'][-1]
          input_dict['int_arv_tm_in'].append(pck_dict['time'] )
          

        if 'length_in' not in input_dict:  input_dict['length_in'] = list()
        input_dict['length_in'].append(pck_dict['length'])
          
        if 'payload_data_length_in' not in input_dict:  input_dict['payload_data_length_in'] = list()
        input_dict['payload_data_length_in'].append(pck_dict['payload_data_length'])
          
          
      elif pck_dict['direction']==0:
        if 'int_arv_tm_out' not in input_dict:
          input_dict['int_arv_tm_out'] = list()
          input_dict['int_arv_tm_out'].append(pck_dict['time'] )
        else:
          input_dict['int_arv_tm_out'][-1] = pck_dict['time'] -input_dict['int_arv_tm_out'][-1]
          input_dict['int_arv_tm_out'].append(pck_dict['time'] )
          

        if 'length_out' not in input_dict:  input_dict['length_out'] = list()
        input_dict['length_out'].append(pck_dict['length'])
        

        if 'payload_data_length_out' not in input_dict:  input_dict['payload_data_length_out'] = list()
        input_dict['payload_data_length_out'].append(pck_dict['payload_data_length'])
          
          
      if 'int_arv_tm_tot' not in input_dict:
        input_dict['int_arv_tm_tot'] = list()
        input_dict['int_arv_tm_tot'].append(pck_dict['time'] )
      else:
        input_dict['int_arv_tm_tot'][-1] = pck_dict['time'] -input_dict['int_arv_tm_tot'][-1]
        input_dict['int_arv_tm_tot'].append(pck_dict['time'] )
        
          
      if 'length_tot' not in input_dict:  input_dict['length_tot'] = list()
      input_dict['length_tot'].append(pck_dict['length'])
        

      if 'payload_data_length_tot' not in input_dict:  input_dict['payload_data_length_tot'] = list()
      input_dict['payload_data_length_tot'].append(pck_dict['payload_data_length'])
      
      return input_dict

    def pck_list_to_feat_dict(pck_list):
      output_dict={}
      if not pck_list: return {}
      for pck_dict in pck_list:
        if pck_dict['addr'] in output_dict.keys():
          output_dict[pck_dict['addr']]=append_feat(pck_dict,output_dict[pck_dict['addr']])
        else:
          output_dict[pck_dict['addr']]=append_feat(pck_dict)
      return output_dict
    
    def math(tmp_list):
      a=round(np.mean(tmp_list),DEC_PLACES_LENGTH)
      b=round(np.std(tmp_list),DEC_PLACES_LENGTH)
      c=round(np.median(np.absolute(tmp_list - np.median(tmp_list))),DEC_PLACES_LENGTH)
      return a,b,c
    
    async def compute(addr,dict_list,time_window):
      output_dict={}
      
      if dict_list is None and addr is None :
        return None
      output_dict['addr']=addr
      output_dict['time']=((self.packet_conv_time-self.first_packet_time).total_seconds()+time_window) if self.feat_cfg.relative_time else self.packet_conv_time
      
      
      tmp_list=np.nan
      if 'int_arv_tm_in' in dict_list : tmp_list=dict_list['int_arv_tm_in'][:-1]
      if not tmp_list:tmp_list=np.nan
      if get_bit(self.feat_cfg.mean_inter_arrival_time ,0): output_dict['in_mean_inter_time'] = round(np.mean(tmp_list),DEC_PLACES_TIME)
      else: tmp_list['in_mean_inter_time'] =''
      if get_bit(self.feat_cfg.std_inter_arrival_time,0): output_dict['in_std_inter_time'] = round(np.std(tmp_list),DEC_PLACES_TIME) 
      else: ''
      if get_bit(self.feat_cfg.mad_inter_arrival_time,0): output_dict['in_mad_inter_time'] = round(np.median(np.absolute(tmp_list - np.median(tmp_list))),DEC_PLACES_TIME) 
      else: ''
      

      tmp_list=np.nan
      if 'int_arv_tm_out' in dict_list:tmp_list=dict_list['int_arv_tm_out'][:-1]
      if not tmp_list:tmp_list=np.nan
      if get_bit(self.feat_cfg.mean_inter_arrival_time ,1): output_dict['out_mean_inter_time'] = round(np.mean(tmp_list),DEC_PLACES_TIME)
      else: ''
      if get_bit(self.feat_cfg.std_inter_arrival_time,1): output_dict['out_std_inter_time'] = round(np.std(tmp_list),DEC_PLACES_TIME)
      else: ''
      if get_bit(self.feat_cfg.mad_inter_arrival_time,1): output_dict['out_mad_inter_time'] = round(np.median(np.absolute(tmp_list - np.median(tmp_list))),DEC_PLACES_TIME)
      else: ''
      
      tmp_list=np.nan
      if 'int_arv_tm_tot' in dict_list:tmp_list=dict_list['int_arv_tm_tot'][:-1]
      if not tmp_list:tmp_list=np.nan
      if get_bit(self.feat_cfg.mean_inter_arrival_time ,2): output_dict['tot_mean_inter_time'] = round(np.mean(tmp_list),DEC_PLACES_TIME)
      else: ''
      if get_bit(self.feat_cfg.std_inter_arrival_time,2): output_dict['tot_std_inter_time'] = round(np.std(tmp_list),DEC_PLACES_TIME)
      else: ''
      if get_bit(self.feat_cfg.mad_inter_arrival_time,2): output_dict['tot_mad_inter_time'] = round(np.median(np.absolute(tmp_list - np.median(tmp_list))),DEC_PLACES_TIME)
      else: ''
      
      tmp_list=np.nan
      if 'length_in' in dict_list:tmp_list=dict_list['length_in']
      mean,std,mad=math(tmp_list)
      if get_bit(self.feat_cfg.mean_size,0): output_dict['in_mean_length'] = mean
      if get_bit(self.feat_cfg.std_size,0): output_dict['in_std_length'] = std
      if get_bit(self.feat_cfg.mad_size,0): output_dict['in_mad_length'] = mad
      if get_bit(self.feat_cfg.count_packets,0): 
        output_dict['in_count'] = 0 if tmp_list is np.nan else len(tmp_list)

      
      
      tmp_list=np.nan
      if 'length_out' in dict_list:tmp_list=dict_list['length_out']
      mean,std,mad=math(tmp_list)
      if get_bit(self.feat_cfg.mean_size,1): output_dict['out_mean_length'] = mean
      if get_bit(self.feat_cfg.std_size,1): output_dict['out_std_length'] = std
      if get_bit(self.feat_cfg.mad_size,1): output_dict['out_mad_length'] = mad
      if get_bit(self.feat_cfg.count_packets,1): 
        output_dict['out_count'] = 0 if tmp_list is np.nan else len(tmp_list)
      
      tmp_list=np.nan
      if 'length_tot' in dict_list:tmp_list=dict_list['length_tot']
      mean,std,mad=math(tmp_list)
      if get_bit(self.feat_cfg.mean_size,2): output_dict['tot_mean_length'] = mean
      if get_bit(self.feat_cfg.std_size,2): output_dict['tot_std_length'] = std
      if get_bit(self.feat_cfg.mad_size,2): output_dict['tot_mad_length'] = mad
      if get_bit(self.feat_cfg.count_packets,2): 
        output_dict['tot_count'] = 0 if tmp_list is np.nan else len(tmp_list)

      tmp_list=np.nan
      if 'payload_data_length_in' in dict_list:tmp_list=dict_list['payload_data_length_tot']
      mean,std,mad=math(tmp_list)
      if get_bit(self.feat_cfg.mean_payload_size ,0): output_dict['in_mean_payload_data_length'] = mean
      if get_bit(self.feat_cfg.std_payload_size,1): output_dict['in_std_payload_data_length'] =  std
      if get_bit(self.feat_cfg.mad_payload_size,1): output_dict['in_mad_payload_data_length'] =  mad
      
      tmp_list=np.nan
      if 'payload_data_length_out' in dict_list:tmp_list=dict_list['payload_data_length_out']
      mean,std,mad=math(tmp_list)
      if get_bit(self.feat_cfg.mean_payload_size ,1): output_dict['out_mean_payload_data_length'] = mean
      if get_bit(self.feat_cfg.std_payload_size,1): output_dict['out_std_payload_data_length'] =  std
      if get_bit(self.feat_cfg.mad_payload_size,1): output_dict['out_mad_payload_data_length'] =  mad
      
      tmp_list=np.nan
      if 'payload_data_length_tot' in dict_list:tmp_list=dict_list['payload_data_length_tot']
      mean,std,mad=math(tmp_list)
      if get_bit(self.feat_cfg.mean_payload_size ,2): output_dict['tot_mean_payload_data_length'] = mean
      if get_bit(self.feat_cfg.std_payload_size,2): output_dict['tot_std_payload_data_length'] =  std
      if get_bit(self.feat_cfg.mad_payload_size,2): output_dict['tot_mad_payload_data_length'] =  mad
      
      return output_dict
    
    window_feat_list=list()
    
    if pck_list is None:
       return window_feat_list
    
    feat_dict=pck_list_to_feat_dict(pck_list)
    
    window_dict_list= await asyncio.gather(*[compute(key,value,time_window) for key,value in feat_dict.items()])
    return window_dict_list

  async def windowed_feat_full_dict(self,pck_list,time_window):
        
    if pck_list is not None:
      if type(pck_list) is dict: pck_list=await self.real_time_dict_direction(pck_list)
      if type(pck_list) is list: self.packet_list.extend(pck_list)
      
    window_list=list()
    feature_dict_list=list()
    try:
      pck_dict=self.packet_list[-1]
      if pck_dict['time'] < time_window:
        return feature_dict_list
      
      window_list = [elem for elem in self.packet_list if elem['time'] <= time_window]
      self.packet_list = [elem for elem in self.packet_list if elem['time'] > time_window]
      for elem in self.packet_list: elem['time']-= time_window
          

      feature_dict_list+=await self.extract_windowed_feat(window_list,time_window)
      
      self.packet_conv_time+=dt.timedelta(seconds=time_window)
      
      feature_dict_list+= await self.windowed_feat_full_dict(None,time_window)
      return feature_dict_list
    
    except IndexError:
      return feature_dict_list
      
  
  def convert_features_to_dict(self,global_dict):
    result = []
    for addr, values in global_dict.items():
      entry = {"addr": addr}
      for key, welford_obj in values.items():
        if 'memory' not in key:
          if 'count' in key:
            entry[key]= welford_obj
          else:
            key_mean = f"{key}_mean"
            key_std = f"{key}_std"
            entry[key_mean] = welford_obj.mean
            entry[key_std] = math.sqrt(welford_obj.var_s) if welford_obj.var_s is not None else None
      result.append(entry)
    return result
  
  async def windowed_feat_welford_dict(self,pck_dict:dict,time_window):  
        
    def init_global_dict(global_dict,var_name:str,var:int):

      if var_name == 'count':
        global_dict[var_name+'_in'] = 0
        global_dict[var_name+'_out'] = 0
        global_dict[var_name+'_tot'] = 0
        return global_dict
      
      
      global_dict[var_name+'_in'] = Welford()
      
      if var_name == 'inter_arrival_time':
        global_dict[var_name+'_in_memory'] = None
        
      global_dict[var_name+'_out'] = Welford()
      if var_name == 'inter_arrival_time':
        global_dict[var_name+'_out_memory'] = None
    
      global_dict[var_name+'_tot'] = Welford()
      
      return global_dict

    def update_global_dict(global_dict,pck_var,direction,var_name:str,var:int):
      
      if var_name == 'inter_arrival_time':
        if not direction:
          if global_dict[var_name+'_in_memory'] is None:
            global_dict[var_name+'_in_memory'] = pck_var
          else:
            global_dict[var_name+'_in'].add(np.array(pck_var - global_dict[var_name+'_in_memory']))
            global_dict[var_name+'_in_memory'] = pck_var
        else:
          if global_dict[var_name+'_out_memory'] is None:
            global_dict[var_name+'_out_memory'] = pck_var
          else:
            global_dict[var_name+'_out'].add(np.array(pck_var - global_dict[var_name+'_out_memory']))
            global_dict[var_name+'_out_memory'] = pck_var
            
      elif var_name == 'count':
        if direction:
          global_dict[var_name+'_out']+=1
          global_dict[var_name+'_tot']+=1
        else:
          global_dict[var_name+'_in']+=1
          global_dict[var_name+'_tot']+=1
          
      else:
        if direction:
          global_dict[var_name+'_out'].add(np.array(pck_var))
          global_dict[var_name+'_tot'].add(np.array(pck_var))
        else:
          global_dict[var_name+'_in'].add(np.array(pck_var))
          global_dict[var_name+'_tot'].add(np.array(pck_var))
          
      return global_dict
      
    def append_feat(pck_dict,direction,dict_key,global_dict=None):
      if global_dict is None:
        global_dict={}
        
        global_dict= init_global_dict(global_dict,var_name = 'inter_arrival_time',var = 7)
        global_dict= init_global_dict(global_dict,var_name = 'size',var = 7)
        global_dict= init_global_dict(global_dict,var_name = 'payload_size',var = 7)
        global_dict= init_global_dict(global_dict,var_name = 'count',var = 7)
        
      global_dict= update_global_dict(global_dict,pck_dict['time'],direction,var_name = 'inter_arrival_time',var = 7)
      global_dict= update_global_dict(global_dict,pck_dict['length'],direction,var_name = 'size',var = 7)
      global_dict= update_global_dict(global_dict,pck_dict['payload_data_length'],direction,var_name = 'payload_size',var = 7)
      global_dict= update_global_dict(global_dict,1,direction,var_name = 'count',var = 7)
      
      return global_dict
      
    def src_dest_addr_feat(pck_dict:dict,dict_key:str,direction:bool):
      if dict_key in pck_dict.keys():
        if pck_dict[dict_key] in self.store_features_memory.keys():
          self.store_features_memory[pck_dict[dict_key]]=append_feat(pck_dict,direction,dict_key,self.store_features_memory[pck_dict[dict_key]])
        else:
          self.store_features_memory[pck_dict[dict_key]]=append_feat(pck_dict,direction,dict_key)
  

    if pck_dict is None:
      return False
    src_dest_addr_feat(pck_dict,'dest_addr',1)
    src_dest_addr_feat(pck_dict,'src_addr',0)
    return True
  
  
  async def acquire_features_welford(self,raw_pck:Union[bytes, bytearray],time,head_pck:header_154=None,dbm=None):
    
    async def compute_real_time_feat():
      if self.feat_cfg.formatting_type:
        result = await self.real_time_dict_direction(pck_dict,self.feat_cfg.relative_time)
      else:
        result = await self.real_time_dict(pck_dict,self.feat_cfg.relative_time)
      
      if self.feat_cfg.topology_map:
        pass
        #top_data_task = asyncio.create_task(self.topology_map(pck_dict))
        #extract_data['topology']=self.topology_map(pck_dict)
        
      if result is not None:
        if self.extract_data_memory is None:
          self.extract_data_memory={"features":[],"topology":[]}
        self.extract_data_memory['features']=self.extract_data_memory['features'] + result

    if raw_pck is None or time is None:
      return False
    
    deep_pcaket_inspection = ( self.feat_cfg.payload_data_length or self.feat_cfg.mad_payload_size or self.feat_cfg.mean_payload_size or self.feat_cfg.std_payload_size )
    #To Do decide which dissector to use based on if dpi is requested
    if deep_pcaket_inspection:
      pck_dict=self.extract_info_scapy(raw_pck,time,dbm,self.feat_cfg.topology_map)
    else:
      if head_pck is None: 
        zb_dissect = ZbDissector()
        head_pck = zb_dissect.packet_dissecting(raw_pck)
        
      pck_dict=self.extract_info_header(head_pck,time,dbm,self.feat_cfg.topology_map)
    
    
    if pck_dict is None:
      return False
  
    if not self.feat_cfg.time_window:
       asyncio.create_task(compute_real_time_feat())  
    else:
      if self.feat_cfg.topology_map:
        pass

      asyncio.create_task(self.windowed_feat_welford_dict(pck_dict,abs(self.feat_cfg.time_window)))
    
    return True
    
    
  
  async def acquire_features_raw(self,raw_pck:Union[bytes, bytearray],time,head_pck:header_154=None,dbm=None):
    extract_data={"features":[],"topology":[]}
    
    if raw_pck is None or time is None:
      return None
    
    deep_pcaket_inspection = ( self.feat_cfg.payload_data_length or self.feat_cfg.mad_payload_size or self.feat_cfg.mean_payload_size or self.feat_cfg.std_payload_size )
    #To Do decide which dissector to use based on if dpi is requested
    if deep_pcaket_inspection:
      pck_dict=self.extract_info_scapy(raw_pck,time,dbm,self.feat_cfg.topology_map)
    else:
       if head_pck is None: 
         zb_dissect = ZbDissector()
         head_pck = zb_dissect.packet_dissecting(raw_pck)
         
       pck_dict=self.extract_info_header(head_pck,time,dbm,self.feat_cfg.topology_map)
    
    
    if pck_dict is None:
      return extract_data
    
    feat_data_task = None
    top_data_task = None
    
    if not self.feat_cfg.time_window:
      if self.feat_cfg.formatting_type:
        feat_data_task = asyncio.create_task(self.real_time_dict_direction(pck_dict,self.feat_cfg.relative_time))
        #extract_data['features']=self.real_time_dict_direction(pck_dict,self.feat_cfg.relative_time)
      else:
        feat_data_task = asyncio.create_task(self.real_time_dict(pck_dict,self.feat_cfg.relative_time))
        #extract_data['features']=self.real_time_dict(pck_dict,self.feat_cfg.relative_time)
      
      if self.feat_cfg.topology_map:
        pass
        #top_data_task = asyncio.create_task(self.topology_map(pck_dict))
        #extract_data['topology']=self.topology_map(pck_dict)
    else:
      if self.feat_cfg.topology_map:
        pass
        #top_data_task = asyncio.create_task(self.topology_map(pck_dict))
        #extract_data['topology']=self.topology_map(pck_dict)
        
      feat_data_task=asyncio.create_task(self.windowed_feat_full_dict(pck_dict,abs(self.feat_cfg.time_window)))
      #feat_data_task=asyncio.create_task(self.windowed_feat_dict(pck_dict,abs(self.feat_cfg.time_window)))
      #extract_data['features']=self.windowed_feat_df(pck_dict,abs(self.feat_cfg.time_window))
      
    if feat_data_task is not None:
      extract_data['features'] = await feat_data_task
    if top_data_task is not None:
      extract_data['topology']= await top_data_task
      
    return extract_data
  
  
  
    
class Analytic:
  """
  Class which will handle the acquisition of the packets and the creation of the files
  """
  def __init__(self,queue:asyncio.Queue,dest_dir="./forensic_capture/",
               file_cfg:FilesConfig=FilesConfig(),
               feat_cfg:FeaturesConfig=FeaturesConfig()) -> None:
    self._queue=queue
    self.dest_dir = dest_dir
    self.status:int = 0
    self.path:str = None
    self.file_cfg=file_cfg
    self.feat_cfg=feat_cfg
    
    self.packetcount: int = 0
    self.filecount: int = 0
    self.start_capture_time:datetime = None
    self.execution_task= None
    
  
  def get_status(self):
    my_dict:dict = {}
  
    whitelsit_types = [str,int]

    for key, value in self.__dict__.items():
        if type(value) in whitelsit_types:
            my_dict[key]=value
    return my_dict
  
  
  def reduced_get_status(self):
    my_dict:dict = {}
    my_dict['status'] = self.status
    return my_dict
  
  def get_queue_used(self):
    return self._queue

  def set_queue (self,queue:asyncio.Queue):
    self._queue=queue
    
  def new_path (self,old_id,new_id=None):
    """Create a new path removing the old index and add a new index, in case index is not passed it will automatically create a +1 index"""
    suf_path = "_%d" % old_id
    if not new_id:
      new_id=old_id+1
    return suf_path.join(self.path.split(suf_path)[:-1]) + "_%d" % new_id

  def set_dest_path(self,dest_dir):
    """Method to update the destination path after the object creation, if left to none the destination path will be set as default one"""
    self.dest_dir=dest_dir
    return True

  async def force_stop(self):
    """Function which will close the running Acquisition"""
    if self.execution_task:
      if not self.execution_task.cancelled(): self.execution_task.cancel()
    self.status = 0
    self.packetcount=0
    self.filecount = 1
  
  def __stop_acquire(self):
    """Function which will close the running Acquisition"""  
    self.status = 0
    self.packetcount=0
    self.filecount = 1
    _LOGGER.debug("PCAP Acquiring stopped at time %s" %  dt.datetime.now().strftime('%Y_%m_%d_%H_%M_%S'))

  
  async def start_acqure(self,frequency=None,file_cfg:FilesConfig=None,feat_cfg:FeaturesConfig=None,async_func_handler=None):
    if file_cfg is not None: self.file_cfg=file_cfg
    if feat_cfg is not None: self.feat_cfg=feat_cfg
    
    if type(self) is Pcap_Analytic:
      file_path_type = PCAP_FILE_PATH
      if frequency is None: raise ValueError
      else: self.frequency=frequency
    if type(self) is Features_Analytic: file_path_type = FEAT_FILE_PATH
    

    self.packetcount=0
    self.filecount = 1
    
    """Creation of a new file named by the creation time 2000_12_28_11_30_45, in case the option for max size is set a folder is created"""
    self.start_capture_time=dt.datetime.now()
    pcap_end_path=self.start_capture_time.strftime('%Y_%m_%d_%H_%M_%S')
    self.path = os.path.join(self.dest_dir, file_path_type)
    if self.path and not os.path.exists(self.path):
        os.makedirs(self.path)
        
    self.path = os.path.join(self.path, pcap_end_path)
    
    if os.path.exists(self.path):
      self.path=self.path+"_new"
    
    if self.file_cfg.pcap_split_size:
      if self.path and not os.path.exists(self.path):
        os.makedirs(self.path)
      self.path = os.path.join(self.path,pcap_end_path+"_%d"% self.filecount)
    if async_func_handler is None: async_func_handler=asyncio.create_task
    self.execution_task= async_func_handler(self.consume_packets(async_func_handler))
    
    
  async def consume_packets(self,async_func_handler):
    pass
  

class Features_Analytic(Analytic):
  """
  Class which will handle the acquisition of the packets and the creation of the files for the features (real time and Pcap)
  """
  def __init__ (self,queue:asyncio.Queue,dest_dir="./forensic_capture/",
                file_cfg:FilesConfig=FilesConfig(),
                feat_cfg:FeaturesConfig=FeaturesConfig()):
    super().__init__(queue,dest_dir,file_cfg,feat_cfg)
    
    self.analyzer = zbAnalyzePackets(self.feat_cfg)
    self.write_head=1
  
  async def feature_dump(self,packet):
    """
    Function which will write the features to the file extracted from the packet
    Args:
        packet (Dict): Dictionary containing the packet raw information
    """
    
    file_path=self.path + FEAT_FILE_EXTENSION
    analyzer=self.analyzer
    extracted_data=await analyzer.acquire_features_raw(packet['bytes'],packet['datetime'],packet["header"],packet["dbm"])
    if extracted_data is not None and type(extracted_data['features'])==list:
      if extracted_data['features']: #not extracted_data['features'].empty:
        #ToDo fix this
        #for di in extracted_data['features']:
        #  for key in di:
        #    if np.isnan(di[key]):di[key]=''
        
        with open(file_path, 'a', newline='') as csvfile:
          writer = csv.DictWriter(csvfile, fieldnames=extracted_data['features'][0].keys(),delimiter=analyzer.feat_cfg.csv_separator)
          if self.write_head:
              writer.writeheader()
              self.write_head=0
          writer.writerows(extracted_data['features'])
    elif extracted_data is not None and type(extracted_data['features'])==pd.DataFrame:
      if not extracted_data['features'].empty:
        extracted_data['features'].to_csv(file_path, mode='a',sep=analyzer.feat_cfg.csv_separator, index=False, header=self.write_head)
        if self.write_head: self.write_head=0
  
  
  async def write_every_n_sec(self):
    file_path=self.path + FEAT_FILE_EXTENSION
    while self.status == 1:
      await asyncio.sleep(self.analyzer.feat_cfg.time_window)
      features_to_write:dict = self.analyzer.get_welford()
      if features_to_write is not None:
        with open(file_path, 'a', newline='') as csvfile:
          writer = csv.DictWriter(csvfile, fieldnames=features_to_write['features'][0].keys(),delimiter=self.analyzer.feat_cfg.csv_separator)
          if self.write_head:
              writer.writeheader()
              self.write_head=0
          writer.writerows(features_to_write['features'])
        self.analyzer.reset_welford()
    
  
  async def consume_packets(self,async_func_handler):
    """
    Get packets from the queue and pass them to feature_dump function
    """
    if self.status==0:
      self.status=1
      asyncio.create_task(self.write_every_n_sec())
        
    """Create a csv file"""
    try:
        await asyncio.sleep(0.005)
        packet = await self._queue.get()
        if not packet:
            return False
        
        self.packetcount+=1
        #asyncio.create_task(self.feature_dump(packet))
        asyncio.create_task(self.analyzer.acquire_features_welford(packet['bytes'],packet['datetime'],packet["header"],packet["dbm"]))
        if (
        (self.file_cfg.pcap_max_packets and self.packetcount > self.file_cfg.pcap_max_packets) or
        (self.file_cfg.pcap_max_time and (dt.datetime.now() >  self.start_capture_time + dt.timedelta(seconds=self.file_cfg.pcap_max_time)))
        ):
          self.__stop_acquire()
          return self.packetcount
        
        #TODO Put a While true and a better stop acquire mechanism. Wait for the queue to be empty
        self.execution_task= async_func_handler(self.consume_packets(async_func_handler))
        return self.packetcount
    except asyncio.CancelledError:     
      self.__stop_acquire()
      return self.packetcount
      

class Pcap_Analytic(Analytic):
  """
  Class which will handle the acquisition of the packets and the creation of the PCAP file
  Get packets from the queue and write them to the pcap saved in dest_dir
  """
  
  def __init__ (self,queue:asyncio.Queue,dest_dir="./forensic_capture/",
                file_cfg:FilesConfig=FilesConfig(),
                feat_cfg:FeaturesConfig=FeaturesConfig()):
    super().__init__(queue,dest_dir,file_cfg,feat_cfg)
    self.pcap_dumper: Optional[PcapDumper] = None
      
  def __create_pcap_dump (self,new=0):
    """Create a pcap_dump object in a secure way.
    Close the Open PCAP dumper if not None and create a new one"""
    if self.pcap_dumper is not None:
      if not new: return self.pcap_dumper
      self.pcap_dumper.close()
    return PcapDumper(DLT_IEEE802_15_4, self.path + PCAP_FILE_EXTENSION)
  
  
  async def force_stop(self):
    """Function which will close the PCAP Acquisition running"""
    self.pcap_dumper.close()
    await super().force_stop()
    _LOGGER.debug("PCAP Acquiring stopped at time %s" %  dt.datetime.now().strftime('%Y_%m_%d_%H_%M_%S'))
  
  
  def __stop_acquire(self):
    """Function which will close the PCAP Acquisition running"""
    self.pcap_dumper.close()
    self.status = 0
    self.packetcount=0
    self.filecount = 1
    _LOGGER.debug("PCAP Acquiring stopped at time %s" %  dt.datetime.now().strftime('%Y_%m_%d_%H_%M_%S'))
  
         
  async def consume_packets(self,async_func_handler):
    """
    Create a pcap dump object
    Get packets from the queue and write them to the pcap file
    """  
    self.pcap_dumper = self.__create_pcap_dump()
    #_LOGGER.debug("PCAP Acquiring started at time %s" %  self.start_capture_time.strftime('%Y_%m_%d_%H_%M_%S'))
    self.status=1
    try:
      #await asyncio.sleep(0.005)
      packet = await self._queue.get()
      if not packet:
          return False
      
      self.pcap_dumper.pcap_dump(packet["bytes"], ant_dbm=packet["dbm"], freq_mhz=self.frequency)
      self.packetcount+=1
        
      if self.file_cfg.pcap_split_size and (os.stat(self.path+PCAP_FILE_EXTENSION).st_size >= self.file_cfg.pcap_split_size):
        self.filecount+=1
        self.path= self.new_path(self.filecount-1,self.filecount)
        self.pcap_dumper = self.__create_pcap_dump(new=1)
        
      if ((self.file_cfg.pcap_max_packets and self.packetcount > self.file_cfg.pcap_max_packets) or
          (self.file_cfg.pcap_max_time and (dt.datetime.now() >  self.start_capture_time + dt.timedelta(seconds=self.file_cfg.pcap_max_time))) or
          (self.file_cfg.pcap_max_files and self.filecount > self.file_cfg.pcap_max_files)
          ):
        self.__stop_acquire()
        return self.packetcount
      
      self.execution_task= async_func_handler(self.consume_packets(async_func_handler))
    except asyncio.CancelledError :
      self.__stop_acquire()
      return self.packetcount
    
