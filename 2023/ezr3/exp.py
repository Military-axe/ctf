
"""
idc script
from ida_bytes import *

addr=0x0B6D0
d1 = []
for y in range(6):
    for i in range(6):
        d1.append(int.from_bytes(get_bytes(addr-0x90+i*0x30+y*8, 4),'little'))

print(d1)
"""
key = [
    3361,
    4878,
    2225,
    1471,
    8330,
    273,
    157,
    136,
    2719,
    4412,
    3714,
    3356,
    2379,
    1158,
    6866,
    1097,
    1725,
    9102,
    969,
    8239,
    9195,
    5969,
    3310,
    5977,
    3135,
    8752,
    3198,
    2766,
    9094,
    299,
    6121,
    9396,
    1067,
    6292,
    5076,
    8525,
]
auth = [
    0x0003BC69,
    0x000D3FA0,
    0x0003A94A,
    0x00044AFF,
    0x00045254,
    0x0000CDD1,
    0x00001815,
    0x00003B08,
    0x00070868,
    0x000C6560,
    0x00065662,
    0x000855C8,
    0x0000DCF6,
    0x00004CE6,
    0x0014EEC2,
    0x0002CFD6,
    0x00032766,
    0x0014F6BA,
    0x00025E69,
    0x0006A9A3,
    0x00121EBD,
    0x0005991C,
    0x00050016,
    0x00004A3D,
    0x00097485,
    0x0008D0A0,
    0x0003B916,
    0x00054C58,
    0x00096F94,
    0x00010334,
    0x000DAD22,
    0x0004B234,
    0x0002FE96,
    0x000F33CC,
    0x0012C1E8,
    0x00148F9E,
]
for i in range(len(key)):
    auth[i] ^= key[i]
c = [auth[i] // key[i] for i in range(len(auth))]

def enc(k: list) -> list:
    for i in range(len(k)):
        t = (k[i] & 0xF) << 4 | (k[i] >> 4)
        k[i] = t ^ k[len(k) - 1 - i]
    return k


def dec(k: list) -> list:
    k = k[::-1]
    for i in range(len(k)):
        t = k[i] ^ k[len(k) - 1 - i]
        k[i] = (t & 0xF) << 4 | (t >> 4)
    return k[::-1]


print(bytes(dec(c)))
