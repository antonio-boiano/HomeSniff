from zbanalytics import *
from zbdump import *

import asyncio




async def main_feat():
    snf = AsyncDump(11)
    await snf.start_dump()
    queue_f=snf.subscribe()
    snf_analyzer=Features_Analytic(queue_f)
    snf_analyzer.analyzer.feat_cfg.topology_map = 0
    snf_analyzer.analyzer.feat_cfg.time_window = 0
    await snf_analyzer.start_acqure()

async def main_pcap():
    snf = AsyncDump(11)
    await snf.start_dump()
    
    queue=asyncio.Queue()
    await snf.subscribe(queue)

    anal_zb=Pcap_Analytic(queue)
    await anal_zb.start_acqure(snf.get_frequency())


if __name__ == "__main__" :
    loop = asyncio.get_event_loop()
    #Insert here the function to test
    loop.create_task(main_feat())
    loop.run_forever()



