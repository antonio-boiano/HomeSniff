
import struct
from typing import Optional
from zb_dissector_filter import *
import asyncio
import numpy as np

def get_param(packet,subject):
    try:
        get_result = getattr(packet, subject)
        return get_result
    except:
        return np.nan

def main():
    fil = ZbFiltering()
    dis = ZbDissector()



    # Example packet in hex format
    packet_hex = "6188888f95322ad1b04806322a00001d8f0100d1b028cf450000d8e3350e3638c1a40080a1a08893ff6b7d057866c1ffff421ce5e589fc"

    # Convert the hex string to a bytes object
    packet = bytes.fromhex(packet_hex)

    expression = 'wpan.frame_type == 0x1 and wpan.src16 == 0xb0d1'

    print(fil.verify(packet,expression))
    b=dis.packet_dissecting(packet)
    print(get_param(b,'dst16'))



if __name__ == "__main__" :
    # loop = asyncio.get_event_loop()
    # #Insert here the function to test
    # loop.create_task(main())
    # loop.run_forever()
    main()