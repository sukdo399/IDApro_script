from idaapi import Form
from struct import *
import idc
import idaapi
import idautils
import os

class MyForm(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM 0
Pick Symbol File
<#Select a file to open#Browse to open:{iFileOpen}>""", {'iFileOpen': Form.FileInput(open=True)})

def get_filename(fn):
    global f
    f = MyForm()
    f.Compile()
    f.iFileOpen.value = fn
    ok = f.Execute()
    
    if ok == 1:
        rtn = f.iFileOpen.value
    else:
        rtn = "*.*"
        
    f.Free()
    return rtn

fn="*.*"
#fn = "Q:\\tplink\\wr886nv5_160704_typeB\\SYMBOL.bin"
while (not os.path.isfile(fn)) :
    fn = get_filename(fn)
    if fn == "*.*":
        break;
    
if fn == "*.*":
    exit

with open(fn,"rb") as f:
    ENT=f.read()
print "%s File read done." % fn

TOT_SZ=unpack('>L',ENT[:4])[0]
TOT_CNT=unpack('>L',ENT[4:8])[0]

if TOT_SZ != len(ENT):
    print "File size does not match"
    exit

printable = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.<>"

SetStatus(IDA_STATUS_WAITING)

for i in range(TOT_CNT):
    ofs=i*0x8+0x08
    str_ofs=unpack('>L',ENT[ofs:ofs+4])[0] & 0xFFFFFF
    tgt_ofs=unpack('>L',ENT[ofs+4:ofs+8])[0]
    str_str=ENT[8 + 8*TOT_CNT + str_ofs:].split("\x00")[0]
    print "%s %d %x" %(str_str,str_ofs,tgt_ofs)
    
    idc.MakeFunction(tgt_ofs)
    if idc.MakeNameEx(tgt_ofs,str_str,0x100) :
        while not idc.MakeNameEx(tgt_ofs,str_str,0x100) :
            str_str = str_str + "_"

SetStatus(IDA_STATUS_READY)
print "\n\nWork DONE\n"
