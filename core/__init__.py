import logging
_LOGGER = logging.getLogger(__name__)

from typing import Union
import base64
import asyncio

try:
    from .zbconst import DEFAULT_QUEUE_BUFFER_SIZE
    from .zbdump import AsyncDump
    from .zbanalytics import Pcap_Analytic,FilesConfig,Features_Analytic, FeaturesConfig
except ImportError:
    from zbconst import DEFAULT_QUEUE_BUFFER_SIZE
    from zbdump import AsyncDump
    from zbanalytics import Pcap_Analytic,FilesConfig,Features_Analytic, FeaturesConfig
    

PCAP_PS = 'pcap_ps'
FEAT_PS = 'feat_ps'

class IotForensics:
    """Sniffer and Analytic class."""
    KillerBee = AsyncDump.KillerBee
    """Include the File configuration class"""
    FilesConfig = FilesConfig
    """Include the Fatures Configuration Class"""
    FeaturesConfig = FeaturesConfig
    
    def __init__(self,snf_channel=11, dev_path=None, hardware=None,kb=None) -> None:
        """Initialize the system."""
        self.snf_channel = snf_channel if snf_channel is not None else 11 
        self.snf = AsyncDump(self.snf_channel,dev_path=dev_path, hardware=hardware,kb=kb)
        self.list_of_process = {PCAP_PS:{},FEAT_PS:{}}
       
    
    async def start (self,kb=None,async_handler=None):
        """Start to dump packets. They will be discharged until a new process is generated with the start_capture method"""
        try:
            await self.snf.start_dump(async_handler=async_handler)
        except:
            _LOGGER.error("Could not create device sniffer instance, check device")
            raise
        
    async def shutdown (self):
        """All running processes are stopped and the dumper application is shout down, freeing the Hardware"""
        await self.delete_capture_process()
        self.snf.shutdown()
        
    
    def get_status(self,pcap_status=1,features_status=1):
        """
        Returns a dictionary containing the status of PCAP processes and features processes.
        If pcap_status is set to 1, it will return the status of all PCAP processes. 
        If features_status is set to 1, it will return the status of all feature processes. 
        
        :param pcap_status: (int) set to 1 to include PCAP process status in the returned dictionary.
        :param features_status: (int) set to 1 to include feature process status in the returned dictionary.
        :return: (dict) containing the status of PCAP processes and features processes.
        """
        status:dict={PCAP_PS:{},FEAT_PS:{}}
        
        if pcap_status:
            for key ,val in self.list_of_process[PCAP_PS].items():
                status[PCAP_PS][key]=val.reduced_get_status()
        if features_status:
            for key ,val in self.list_of_process[FEAT_PS].items():
                status[FEAT_PS][key]=val.reduced_get_status()
        return status
    
    def create_unique_id_from_obj(self,input):
        """
        Creates a unique id from an input object.
        The unique id is created by converting the memory address of the input object to bytes and encoding it using base64.
        
        :param input: (object) the input object for which a unique id is to be created.
        :return: (str) unique id for the input object.
        """
        id_b=id(input).to_bytes((id(input).bit_length() + 7) // 8, 'big')
        return base64.b64encode(id_b).decode('utf-8')
    
    
    async def start_features_capture(self,snf_file_path, object_id=None,
                                     file_config: Union[FilesConfig, dict] = None, # type: ignore
                                     features_config:Union[FeaturesConfig,dict] = None, # type: ignore
                                     async_func_handler=None,
                                     blocking = False):
        
        """
        Starts capture of features and saves it to a given file destination path, if an object id is provided it will use it, 
        otherwise it will create a new object.
        It initialize the FileConfig and FeaturesConfig objects if they are not provided.
        It sets up a queue and subscribes to it, then it creates a Features_Analytic object and sets its queue,
        destination directory and configurations.
        Then it starts the acquisition process.
        
        :param snf_file_path: (str)  the path where the features capture will be saved
        :param object_id: (str) the id of the object to be used, if None a new object will be created
        :param file_config: (FilesConfig | dict) configuration for the Files_Analytic object
        :param features_config: (FeaturesConfig | dict) configuration for the Features_Analytic object
        
        Returns:
        None
        """
        
        if file_config is None: file_config = FilesConfig()
        if features_config is None: features_config = FeaturesConfig()
        
        if type(file_config) is dict: file_config = FilesConfig(**file_config)
        if type(features_config) is dict: features_config = FeaturesConfig(**features_config)
    
        read_task = None
        
        if features_config is not None:
            if features_config.pcap_file_path is None: queue = self.snf.subscribe()
        else:
            queue, read_task = await self.snf.read_pcap(features_config.pcap_file_path)
        
        if queue is None:
            raise ValueError
        
        if object_id in self.list_of_process[FEAT_PS]:
            snf_feat:Features_Analytic = self.list_of_process[FEAT_PS][object_id]
            snf_feat.set_queue(queue)
        else:
            try:
                snf_feat = Features_Analytic(queue=queue,dest_dir=snf_file_path,file_cfg=file_config,feat_cfg=features_config)
            except Exception as e:
                _LOGGER.error("Could not create analytic sniffer instance"+str(e))
                raise e
                
        snf_feat.set_dest_path(snf_file_path)
        
        id =self.create_unique_id_from_obj(snf_feat)
        self.list_of_process[FEAT_PS][id]=snf_feat
        
        await snf_feat.start_acqure(async_func_handler=async_func_handler)
        
        if read_task and blocking: await read_task
    
     
    
    async def start_pcap_capture(self,snf_file_path, object_id=None,
                                 file_config:FilesConfig=FilesConfig(),
                                 features_config:FeaturesConfig = FeaturesConfig(),
                                 async_func_handler=None):

        """
        Start PCAP capture process.
        
        Parameters:
        snf_file_path (str): path to save the captured pcap files.
        object_id (str, Optional): Id of the capture process. If not provided, a unique id will be generated.
        file_config (FilesConfig, Optional): Configuration for the pcap file.
        features_config (FeaturesConfig, Optional): Configuration for the features.
        
        Returns:
        None
        """

        if type(file_config) is dict: file_config = FilesConfig(**file_config)
        if type(features_config) is dict: features_config = FeaturesConfig(**features_config)
        
        queue = self.snf.subscribe()
        if object_id in self.list_of_process[PCAP_PS]:
            snf_pcap:Pcap_Analytic = self.list_of_process[PCAP_PS][object_id]
            snf_pcap.set_queue(queue)
        else:
            try:
                snf_pcap = Pcap_Analytic(queue=queue,dest_dir=snf_file_path,file_cfg=file_config,feat_cfg=features_config)
            except:
                _LOGGER.error(
                "Could not create analytic sniffer instance"
                )
                raise Exception
            
            id =self.create_unique_id_from_obj(snf_pcap)
            self.list_of_process[PCAP_PS][id]=snf_pcap
                
        snf_pcap.set_dest_path(snf_file_path)
        snf_frequency = self.snf.get_frequency()
        await snf_pcap.start_acqure(frequency=snf_frequency,async_func_handler=async_func_handler)
    
    
    async def stop_capture(self,process_id=None):
        """
        stop_capture - stops a capture process, either a specific process or all processes
        :param process_id: (Optional) ID of the process to stop. If not provided, all processes are stopped
        :type process_id: str
        """
        
        for ps_list in self.list_of_process.values():
            
            if  process_id in ps_list:
                snf_ps  = ps_list[process_id]
                await snf_ps.force_stop()
                queue=snf_ps.get_queue_used()
                self.snf.unsubscribe(queue)
                break
            
            else:
                for value in ps_list.values():
                    await value.force_stop()
                    queue=value.get_queue_used()
                    self.snf.unsubscribe(queue)
    
    
    async def delete_capture_process(self,process_id=None):
        """
        This method stops a capture process and removes it from the list of current processes being tracked.

        Parameters:
        process_id (str, optional): The unique ID of the process to be deleted. If None, all processes will be deleted.
        """
        await self.stop_capture(process_id)
        if process_id is not None:
            for ps_list in self.list_of_process.values():
                if process_id in ps_list: ps_list.pop(process_id)
        else:
            self.list_of_process.clear()
            self.list_of_process = {PCAP_PS:{},FEAT_PS:{}}
    