import logging
import voluptuous as vol


from homeassistant.const import (
    CONF_DEVICE,
    CONF_DEVICE_CLASS,
    EVENT_HOMEASSISTANT_STOP,
)
from homeassistant.core import HomeAssistant, ServiceCall, Event
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.typing import ConfigType

from .const import  (
    DOMAIN,
    CONF_SAVE_PATH,
    CONF_MAX_FILES,
    CONF_MAX_PACKETS,
    CONF_MAX_TIME,
    CONF_MAX_SIZE,
    CONF_SPLIT_SIZE,
    CONF_FILTER,
    OBJ_ID,
    CONF_TOP_MAP,
    CONF_TIME_WIN,
    CONF_TIMESTAMP,
    CONF_REL_TIME,
    CONF_LENGTH,
    CONF_PAY_LEN,
    CONF_DBM,
    CONF_FMT_TYPE,
    CONF_SRC,
    CONF_DEST,
    CONF_INCOMING,
    CONF_OUTGOING,
    CONF_MEAN_INT_ARR,
    CONF_MEAN_SIZE,
    CONF_MEAN_PAY_SIZE,
    CONF_STD_INT_ARR,
    CONF_STD_SIZE,
    CONF_STD_PAY_SIZE,
    CONF_MAD_INT_ARR,
    CONF_MAD_SIZE,
    CONF_MAD_PAY_SIZE,
    CONF_CSV_SEP,
    CONF_COUNT,
    )

try:
    import killerbee
except ImportError:
    from . import killerbee

from .core import IotForensics

_LOGGER = logging.getLogger(__name__)

CONF_ZB_CHANNEL = "zb_channel"
DATA_FORENSIC_SNIFFER = "sniffer_obj"

#Service define
SERVICE_START_CAPTURING_PCAP = "start_pcap_capture"
SERVICE_START_FEAT_CAPTURING = "start_feat_capture"
SERVICE_DEL_CAPTURE = "delete_capture"
SERVICE_STOP_CAPTURE = "stop_capture"
SERVICE_GET_STATUS= "get_capture_status"
SERVICE_INIT= "init_capture"
SERVICE_START_MONITOR = "start_monitor"
SERVICE_STOP_MONITOR = "stop_monitor"


CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Optional(CONF_DEVICE): cv.string,
                vol.Optional(CONF_DEVICE_CLASS): vol.In([
                    "apimote",
                    "rzusbstick",
                    "cc2530",
                    "cc2531",
                    "bumblebee",
                    "sl_nodetest",
                    "sl_beehive",
                    "zigduino",
                    "freakdruino",
                    "telosb",
                    "sewio",
                ]
                    ),
                vol.Optional(CONF_ZB_CHANNEL): vol.Coerce(int)
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


SCHEMA_SERVICE_START_FEAT_CAPTURING = vol.Schema(
    {
        vol.Optional(CONF_SAVE_PATH): cv.string,
        vol.Optional(CONF_TOP_MAP): vol.Coerce(int),
        vol.Optional(CONF_TIME_WIN): vol.Coerce(int),
        vol.Optional(CONF_TIMESTAMP): vol.Coerce(int),
        vol.Optional(CONF_REL_TIME): vol.Coerce(int),
        vol.Optional(CONF_LENGTH): vol.Coerce(int),
        vol.Optional(CONF_PAY_LEN): vol.Coerce(int),
        vol.Optional(CONF_DBM): vol.Coerce(int),
        vol.Optional(CONF_FMT_TYPE): vol.Coerce(int),
        vol.Optional(CONF_SRC): vol.Coerce(int),
        vol.Optional(CONF_DEST): vol.Coerce(int),
        vol.Optional(CONF_INCOMING): vol.Coerce(int),
        vol.Optional(CONF_OUTGOING): vol.Coerce(int),
        vol.Optional(CONF_MEAN_INT_ARR): cv.string,
        vol.Optional(CONF_MEAN_SIZE): cv.string,
        vol.Optional(CONF_MEAN_PAY_SIZE): cv.string,
        vol.Optional(CONF_STD_INT_ARR): cv.string,
        vol.Optional(CONF_STD_SIZE): cv.string,
        vol.Optional(CONF_STD_PAY_SIZE): cv.string,
        vol.Optional(CONF_MAD_INT_ARR): cv.string,
        vol.Optional(CONF_MAD_SIZE): cv.string,
        vol.Optional(CONF_MAD_PAY_SIZE): cv.string,
        vol.Optional(CONF_COUNT): cv.string,
        vol.Optional(CONF_FILTER): cv.string,
        vol.Optional(CONF_CSV_SEP): cv.string,
        vol.Optional(OBJ_ID): cv.string,
        
    }
)


SCHEMA_SERVICE_START_CAPTURING_PCAP = vol.Schema(
    {
        vol.Optional(CONF_SAVE_PATH): cv.string,
        vol.Optional(CONF_MAX_TIME): vol.Coerce(int),
        vol.Optional(CONF_MAX_FILES): vol.Coerce(int),
        vol.Optional(CONF_MAX_PACKETS): vol.Coerce(int),
        vol.Optional(CONF_MAX_SIZE): vol.Coerce(int),
        vol.Optional(CONF_SPLIT_SIZE): vol.Coerce(int),
        vol.Optional(CONF_FILTER): cv.string,
        vol.Optional(OBJ_ID): cv.string,  
    }
)

SCHEMA_SERVICE_DEL = vol.Schema(
    {
        vol.Optional(OBJ_ID): cv.string,   
    }
)

SCHEMA_SERVICE_STOP = vol.Schema(
    {
        vol.Optional(OBJ_ID): cv.string,   
    }
)

class Forensic_System:
    
    def __init__(self,channel:int=None,device_path:str=None,hardware_type:str=None,kb=None):
        
        self.entity_ids: set[str | None] = set()
        self.logout_listener = None
        
        self.iot_forensics:IotForensics = IotForensics(snf_channel=channel,dev_path=device_path, hardware=hardware_type, kb=kb)
        
        self.process = None
        self.status=0
        
    async def init(self,async_handler=None):
        self.status=1
        if self.iot_forensics:
            await self.iot_forensics.start(async_handler=async_handler)
    
    async def stop(self):
        self.status=0
        if self.iot_forensics:
            await self.iot_forensics.shutdown()


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    
    """Set up Forensics component"""
    conf = config[DOMAIN]
    device_path = conf.get(CONF_DEVICE)
    hardware_type = conf.get(CONF_DEVICE_CLASS)
    snf_channel = conf.get(CONF_ZB_CHANNEL)
    try:
        _LOGGER.warning('START FIND DEVICE')
        kb=await hass.async_add_executor_job(killerbee.KillerBee, device_path,hardware_type)
        #kb=killerbee.KillerBee(device=device_path,hardware=hardware_type)
        _LOGGER.warning('FIND DEVICE')
        
    except Exception as e:
        _LOGGER.error(e)
        return False
    
    hass.data[DATA_FORENSIC_SNIFFER] = Forensic_System(snf_channel,kb=kb)
     
    await setup_hass_events(hass,config)
    await async_setup_hass_services(hass)
    
    return True
    

async def setup_hass_events(hass: HomeAssistant, config: ConfigType) -> None:
    """Home Assistant start and stop callbacks."""
    
    async def logout(event: Event) -> None:
        """Safe close Sniffer Application."""
        if  hass.data[DATA_FORENSIC_SNIFFER] :
            await hass.data[DATA_FORENSIC_SNIFFER].iot_forensics.shutdown()

    if hass.data[DATA_FORENSIC_SNIFFER]:
        await hass.data[DATA_FORENSIC_SNIFFER].iot_forensics.start()

    hass.data[DATA_FORENSIC_SNIFFER].logout_listener = hass.bus.async_listen_once(
        EVENT_HOMEASSISTANT_STOP, logout
    )

    
async def async_setup_hass_services(hass: HomeAssistant) -> None:
    
    #TODO Use to convert and test websocket_API or understand if there is a way to creat a custom frontend from it
    
    async def start_pcap_capture(call: ServiceCall) -> None:
        """Start the capture of PCAP file"""
        iot_feat:IotForensics=hass.data[DATA_FORENSIC_SNIFFER].iot_forensics   
        #if not hass.data[DATA_FORENSIC_SNIFFER].status:
        #    await hass.data[DATA_FORENSIC_SNIFFER].init(async_handler=hass.async_create_task)
            
        file_cfg_dict={}
        
        obj_id=call.data.get(OBJ_ID)
        snf_file_path = call.data.get(CONF_SAVE_PATH,"./forensic_capture")
        file_cfg_dict['pcap_max_time'] = call.data.get(CONF_MAX_TIME)
        file_cfg_dict['pcap_max_files'] = call.data.get(CONF_MAX_FILES)
        file_cfg_dict['pcap_max_size'] = call.data.get(CONF_MAX_SIZE)
        file_cfg_dict['pcap_max_packets'] = call.data.get(CONF_MAX_PACKETS)
        file_cfg_dict['pcap_split_size'] = call.data.get(CONF_SPLIT_SIZE)
        file_cfg_dict['pcap_split_size'] = call.data.get(CONF_FILTER)
        file_cfg_dict['filter_string']= call.data.get(CONF_FILTER)
        
        await iot_feat.start_pcap_capture(snf_file_path,object_id=obj_id,file_config=file_cfg_dict,async_func_handler=hass.async_create_task)
        
    async def start_feat_capture(call: ServiceCall) -> None:
        """Start the Feature extraction capture"""
        
        #if not hass.data[DATA_FORENSIC_SNIFFER].status:
        #    await hass.data[DATA_FORENSIC_SNIFFER].init(async_handler=hass.async_create_task)
            
        iot_feat:IotForensics=hass.data[DATA_FORENSIC_SNIFFER].iot_forensics 
        
        obj_id=call.data.get(OBJ_ID)
        snf_file_path = call.data.get(CONF_SAVE_PATH,"./forensic_capture")
            
        
        feat_cfg_dict_tmp = {
        "topology_map": call.data.get(CONF_TOP_MAP),
        "time_window": call.data.get(CONF_TIME_WIN),
        "timestamp": call.data.get(CONF_TIMESTAMP),
        "relative_time": call.data.get(CONF_REL_TIME),
        "length": call.data.get(CONF_LENGTH),
        "payload_data_length": call.data.get(CONF_PAY_LEN),
        "dbm": call.data.get(CONF_DBM),
        "formatting_type": call.data.get(CONF_FMT_TYPE),
        "src": call.data.get(CONF_SRC),
        "dest": call.data.get(CONF_DEST),
        "incoming": call.data.get(CONF_INCOMING),
        "outgoing": call.data.get(CONF_OUTGOING),
        "mean_inter_arrival_time": int( call.data.get(CONF_MEAN_INT_ARR),2) if call.data.get(CONF_MEAN_INT_ARR) is not None else None,
        "mean_size": int( call.data.get(CONF_MEAN_SIZE),2) if call.data.get(CONF_MEAN_SIZE) is not None else None,
        "mean_payload_size": int( call.data.get(CONF_MEAN_PAY_SIZE),2) if call.data.get(CONF_MEAN_PAY_SIZE) is not None else None,
        "std_inter_arrival_time": int( call.data.get(CONF_STD_INT_ARR),2) if call.data.get(CONF_STD_INT_ARR) is not None else None,
        "std_size": int( call.data.get(CONF_STD_SIZE),2) if call.data.get(CONF_STD_SIZE) is not None else None,
        "std_payload_size": int( call.data.get(CONF_STD_PAY_SIZE),2) if call.data.get(CONF_STD_PAY_SIZE) is not None else None,
        "mad_inter_arrival_time": int( call.data.get(CONF_MAD_INT_ARR),2) if call.data.get(CONF_MAD_INT_ARR) is not None else None,
        "mad_size": int( call.data.get(CONF_MAD_SIZE),2) if call.data.get(CONF_MAD_SIZE) is not None else None,
        "mad_payload_size": int( call.data.get(CONF_MAD_PAY_SIZE),2) if call.data.get(CONF_MAD_PAY_SIZE) is not None else None,
        "count_packets" : int( call.data.get(CONF_COUNT),2) if call.data.get(CONF_COUNT) is not None else None,
        "filter_string": call.data.get(CONF_FILTER),
        "csv_separator": call.data.get(CONF_CSV_SEP),
        }
        
        feat_cfg_dict ={k: v for k, v in feat_cfg_dict_tmp.items() if v is not None}
        
        
        
        await iot_feat.start_features_capture(snf_file_path,obj_id,features_config=feat_cfg_dict,async_func_handler=hass.async_create_task)
       
       
    async def stop_capture(call: ServiceCall) -> None:
        obj_id=call.data.get(OBJ_ID)
        await hass.data[DATA_FORENSIC_SNIFFER].iot_forensics.stop_capture(obj_id)
        
    async def delete_capture(call: ServiceCall) -> None:
        obj_id=call.data.get(OBJ_ID)
        await hass.data[DATA_FORENSIC_SNIFFER].iot_forensics.delete_capture_process(obj_id)
        
        #status=hass.data[DATA_FORENSIC_SNIFFER].iot_forensics.get_status()
        #if all(value == {} or value is None  for value in status.values()) and hass.data[DATA_FORENSIC_SNIFFER].status:
        #    await hass.data[DATA_FORENSIC_SNIFFER].stop()
            
    #ToDo get a capture status of task status https://superfastpython.com/asyncio-cancel-task/#:~:text=You%20can%20cancel%20a%20task,method%20on%20a%20Task%20object.
    def get_capture_status(call: ServiceCall)->None:
        status = hass.data[DATA_FORENSIC_SNIFFER].iot_forensics.get_status()
        _LOGGER.warning(status)
        hass.states.set(DOMAIN+".capture_status", status)
    
    async def init(call:ServiceCall)->None:
        await hass.data[DATA_FORENSIC_SNIFFER].init()
        
    async def start_monitor(call:ServiceCall)->None:

        
        async def monitor_loop(start_time=None,deltat=None,interval=None,name=None):
            import psutil
            import csv
            import asyncio
            import datetime as dt
            if start_time is None: start_time=dt.datetime.now()
            if deltat is None: deltat=0
            if interval is None: interval = 2
            if name is None: name=f'perf'+str(start_time)[-15:]
            write_head=1
            
            while not deltat or start_time+dt.timedelta(seconds=deltat)>dt.datetime.now():
                await asyncio.sleep(interval)
                dict={}
                cpu=psutil.cpu_percent(interval=0,percpu=False)
                per_cpu = psutil.cpu_percent(interval=0,percpu=True)
                mem = psutil.virtual_memory()
                swap=psutil.swap_memory()

                for idx, usage in enumerate(per_cpu):
                    dict[f"CORE_{idx+1}"] = usage

                dict["CORE_ALL"] = cpu
                dict['mem.available']=mem.available
                dict['mem.percent']=mem.percent

                dict['swap.free']=swap.free
                dict['swap.percent']=swap.percent
                dict['time']=dt.datetime.now()
                
                with open(f'./{name}.csv', 'a') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=dict.keys())
                    if write_head: 
                        writer.writeheader()
                        write_head = 0
                    writer.writerow(dict)

        hass.data[DATA_FORENSIC_SNIFFER].process = hass.async_create_task(monitor_loop())
    
    async def stop_monitor(call:ServiceCall):
        if hass.data[DATA_FORENSIC_SNIFFER].process:
            if not hass.data[DATA_FORENSIC_SNIFFER].process.cancelled(): hass.data[DATA_FORENSIC_SNIFFER].process.cancel()
    
    hass.services.async_register(
        DOMAIN,
        SERVICE_START_FEAT_CAPTURING,
        start_feat_capture,
        schema=SCHEMA_SERVICE_START_FEAT_CAPTURING,
    )
      
    
    hass.services.async_register(
        DOMAIN,
        SERVICE_START_CAPTURING_PCAP,
        start_pcap_capture,
        schema=SCHEMA_SERVICE_START_CAPTURING_PCAP,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_DEL_CAPTURE,
        delete_capture,
        schema=SCHEMA_SERVICE_DEL,
    )
    
    hass.services.async_register(
        DOMAIN,
        SERVICE_STOP_CAPTURE,
        stop_capture,
        schema=SCHEMA_SERVICE_STOP,
    )
    
    hass.services.async_register(
        DOMAIN,
        SERVICE_GET_STATUS,
        get_capture_status,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_INIT,
        init,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_START_MONITOR,
        start_monitor
    )
    
    hass.services.async_register(
        DOMAIN,
        SERVICE_STOP_MONITOR,
        stop_monitor
    )