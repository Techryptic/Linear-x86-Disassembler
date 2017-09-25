#!/usr/bin/python
import commands
import os
import sys
import re
from sys import argv
from os.path import exists

#How to use:
#python disasm.py more_examples

f = open(sys.argv[1], 'rb')
fulldata = f.read()
f.close()
fulldatalen = len(fulldata)
print('\x1b[6;30;42m' + 'X86 Disassembler using Linear Sweep Algorithm' + '\x1b[0m')
print('\x1b[6;30;42m' + 'Created by: Anthony                          ' + '\x1b[0m')
print('\x1b[6;30;42m' + '            Anthonys.io                      ' + '\x1b[0m')
print('\x1b[6;30;42m' + '            Twitter.com/Tech                 ' + '\x1b[0m')
print('\x1b[6;30;42m' + '' + '\x1b[0m')

mod00 = '00'
mod11 = '11'
mod01 = '01'
mod10 = '10'

eax = '000' or '50'
ecx = '001' or '51'
edx = '010' or '52'
ebx = '011' or '53'
esp = '100' or '54'
ebp = '101' or '55'
esi = '110' or '56'
edi = '111' or '57'

eax2 = '000'
ecx2 = '001'
edx2 = '010'
ebx2 = '011'
esp2 = '100'
ebp2 = '101'
esi2 = '110'
edi2 = '111'

opcodetable = ['03,01,23,21,ff']
pushpoplist = [
    '0x50',
    '0x51',
    '0x52',
    '0x53',
    '0x54',
    '0x55',
    '0x56',
    '0x57',
    '0x58',
    '0x59',
    '0x5a',
    '0x5b',
    '0x5c',
    '0x5d',
    '0x5e',
    '0x5f',
    ]

n = 0
i = 0
while i < fulldatalen:
    hexx = hex(ord(fulldata[i]))
    i += 1
    hexxx = hex(ord(fulldata[i + 0]))
    hexbin = re.sub('0x', '', hexx)
    my_hexdata = hexbin
    scale = 16
    num_of_bits = 8
    hexbinuse = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
    nulls = hex(ord(fulldata[i]))

    if nulls == '0x0':
        i += 0
        continue
    if hexx == '0x0':
        i += 0
        continue
    if '0x35' in hexx:
        reg = 'XOR'
        addbytes1 = hex(ord(fulldata[i]))
        addbytes2 = hex(ord(fulldata[i + 1]))
        addbytes3 = hex(ord(fulldata[i + 2]))
        addbytes4 = hex(ord(fulldata[i + 3]))
        addbytes_total = addbytes4 + addbytes3 + addbytes2 + addbytes1
        addbytes_total1 = re.sub('0x', '', addbytes_total)
        print reg + ' eax, 0x' + addbytes_total1
        i += 4
        continue
    if '0x25' in hexx:
        reg = 'AND'
        addbytes1 = hex(ord(fulldata[i]))
        addbytes2 = hex(ord(fulldata[i + 1]))
        addbytes3 = hex(ord(fulldata[i + 2]))
        addbytes4 = hex(ord(fulldata[i + 3]))
        addbytes_total = addbytes4 + addbytes3 + addbytes2 + addbytes1
        addbytes_total1 = re.sub('0x', '', addbytes_total)
        print reg + ' eax, 0x' + addbytes_total1
        i += 4
        continue
    if '0x33' in hexx:

        my_hexdata = hex(ord(fulldata[i - 0]))
        scale = 16
        num_of_bits = 8
        hex1z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1z[:2]
        geto2 = hex1z[-6:-3]
        geto3 = hex1z[-3:]

        getmodplus1 = hex1z[:3]
        getmodplus2 = hex1z[:4]
        getmodplus3 = hex1z[:5]

        if '00' in getmod:
            if '101' in geto3:
                reg = 'XOR'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op2 + ', [0x' + addbytes_total + ']'
                i += 5
                continue
            else:

                reg = 'XOR'
                if geto2 == eax:
                    op1 = 'eax'
                if geto2 == ecx:
                    op1 = 'ecx'
                if geto2 == edx:
                    op1 = 'edx'
                if geto2 == esp:
                    op1 = 'esp'
                if geto2 == ebp:
                    op1 = 'ebp'
                if geto2 == esi:
                    op1 = 'esi'
                if geto2 == edi:
                    op1 = 'edi'

                if geto3 == eax2:
                    op2 = 'eax'
                if geto3 == ecx2:
                    op2 = 'ecx'
                if geto3 == edx2:
                    op2 = 'edx'
                if geto3 == esp2:
                    op2 = 'esp'
                if geto3 == ebp2:
                    op2 = 'ebp'
                if geto3 == esi2:
                    op2 = 'esi'
                if geto3 == edi2:
                    op2 = 'edi'

                print reg + ' ' + op1 + ',[' + op2 + ']'
                i += 1
                continue

        if '10' in getmod:
            reg = 'XOR'
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 2
            continue

        if '01' in getmod:
            reg = 'XOR'
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 2
            continue



    if hexx == '0x3':
        reg = 'ADD'
        hex5 = hex(ord(fulldata[i]))
        hex5 = re.sub('0x', '', hex5)
        my_hexdata = hex5
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto1 = hex1[-6:-3]
        geto2 = hex1[-3:]

        if geto1 == eax:
            op1 = 'eax'

        if geto1 == ecx:
            op1 = 'ecx'

        if geto1 in edx:
            op1 = 'edx'

        if geto1 == esp:
            op1 = 'esp'

        if geto1 == ebp:
            op1 = 'ebp'

        if geto1 == esi:
            op1 = 'esi'

        if geto1 == edi:
            op1 = 'edi'

        if geto2 == eax:
            op2 = 'eax'

        if geto2 == ecx:
            op2 = 'ecx'

        if geto2 == edx:
            op2 = 'edx'

        if geto2 == esp:
            op2 = 'esp'

        if geto2 == ebp:
            op2 = 'ebp'

        if geto2 in esi:
            op2 = 'esi'

        if geto2 in edi:
            op2 = 'edi'

        if getmod == '01':
            nextbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op1 + ', [' + op2 + '+' + nextbyte + ']'
            i += 1
            continue

        if getmod == '10':
            nextbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op1 + ', [' + op2 + '+' + nextbyte + ']'
            i += 1
            continue

        if getmod == '00':

            if geto2 == '101':
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total1 = re.sub('0x', '', addbytes_total)
                print reg + ' ' + op1 + ', [0x' + addbytes_total1 + ']'
                i += 5
                continue
            print reg + ' ' + op1 + ', [' + op2 + ']'
            i += 1
            continue

    if '0x31' in hexx:
        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hexcurrent = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]
        reg = 'NOP'

        if '10010000' in hexcurrent:
            print reg
            continue

        if '11' in getmod:
            reg = 'XOR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax:
                op2 = 'eax'
            if geto3 == ecx:
                op2 = 'ecx'
            if geto3 == edx:
                op2 = 'edx'
            if geto3 == esp:
                op2 = 'esp'
            if geto3 == ebp:
                op2 = 'ebp'
            if geto3 == esi:
                op2 = 'esi'
            if geto3 == edi:
                op2 = 'edi'

            print reg+" "+op2+", "+op1
            i += 1
            continue

        if '00' in getmod:
            reg = 'XOR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' [' + op2 + '], ' + op1
            i += 1
            continue

        if '01' in getmod:
            reg = 'XOR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

        if '10' in getmod:
            reg = 'XOR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

    if '0x19' in hexx:
        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hexcurrent = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]
        reg = 'NOP'

        if '10010000' in hexcurrent:
            print reg
            continue

        if '11' in getmod:
            reg = 'SBB'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' ' + op2 + ', ' + op1
            i += 1
            continue

        if '00' in getmod:
            reg = 'SBB'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' [' + op2 + '], ' + op1
            i += 1
            continue

        if '01' in getmod:
            reg = 'SBB'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

        if '10' in getmod:
            reg = 'SBB'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

    if '0x1b' in hexx:

        my_hexdata = hex(ord(fulldata[i - 0]))
        scale = 16
        num_of_bits = 8
        hex1z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1z[:2]
        geto2 = hex1z[-6:-3]
        geto3 = hex1z[-3:]

        getmodplus1 = hex1z[:3]
        getmodplus2 = hex1z[:4]
        getmodplus3 = hex1z[:5]

        if '00' in getmod:
            if '101' in geto3:
                reg = 'SSB'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op2 + ', [0x' + addbytes_total + ']'
                i += 5
                continue
            else:

                reg = 'SBB'
                if geto2 == eax:
                    op1 = 'eax'
                if geto2 == ecx:
                    op1 = 'ecx'
                if geto2 == edx:
                    op1 = 'edx'
                if geto2 == esp:
                    op1 = 'esp'
                if geto2 == ebp:
                    op1 = 'ebp'
                if geto2 == esi:
                    op1 = 'esi'
                if geto2 == edi:
                    op1 = 'edi'

                if geto3 == eax2:
                    op2 = 'eax'
                if geto3 == ecx2:
                    op2 = 'ecx'
                if geto3 == edx2:
                    op2 = 'edx'
                if geto3 == esp2:
                    op2 = 'esp'
                if geto3 == ebp2:
                    op2 = 'ebp'
                if geto3 == esi2:
                    op2 = 'esi'
                if geto3 == edi2:
                    op2 = 'edi'

                print reg + ' ' + op1 + ',[' + op2 + ']'
                i += 1
                continue

        if '10' in getmod:
            reg = 'SBB'
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 2
            continue

        if '01' in getmod:
            reg = 'SBB'
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 2
            continue

    if '0x1' in hexx:
        reg = 'ADD'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto1 = hex1[-6:-3]
        geto2 = hex1[-3:]

        if geto1 == eax:
            op1 = 'eax'

        if geto1 == ecx:
            op1 = 'ecx'

        if geto1 == edx:
            op1 = 'edx'

        if geto1 == esp:
            op1 = 'esp'

        if geto1 == ebp:
            op1 = 'ebp'

        if geto1 == esi:
            op1 = 'esi'

        if geto1 == edi:
            op1 = 'edi'

        if geto2 == eax:
            op2 = 'eax'

        if geto2 == ecx:
            op2 = 'ecx'

        if geto2 == edx:
            op2 = 'edx'

        if geto2 == esp:
            op2 = 'esp'

        if geto2 == ebp:
            op2 = 'ebp'

        if geto2 in esi:
            op2 = 'esi'

        if geto2 in edi:
            op2 = 'edi'

        if getmod == '01':
            nextbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nextbyte + '],' + op1
            i += 1
            continue

        if getmod == '10':
            nextbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nextbyte + '],' + op1
            i += 1
            continue

        if getmod == '00':
            print reg + ' [' + op2 + '],' + op1

        if getmod == '11':



            print reg + ' ' + op2 + ',' + op1
            i += 1
            continue
        else:



            i += 1
            continue



    if hexx in pushpoplist:

        reg = 'PUSH'
        regpop = 'POP'
        hex1 = bin(ord(fulldata[i - 1]))
        hex1 = re.sub('0b', '', hex1)
        geto2 = hex1[-3:]
        geto3 = hex1[-4:]

        if geto2 == eax:
            op2 = 'eax'

        if geto2 == ecx:
            op2 = 'ecx'

        if geto2 == edx:
            op2 = 'edx'

        if geto2 == esp:
            op2 = 'esp'

        if geto2 == ebp:
            op2 = 'ebp'

        if geto2 == esi:
            op2 = 'esi'

        if geto2 == edi:
            op2 = 'edi'

        if geto3 == eax2:
            op2pop = 'eax'

        if geto3 == ecx2:
            op2pop = 'ecx'

        if geto3 == edx2:
            op2pop = 'edx'

        if geto3 == esp2:
            op2pop = 'esp'

        if geto3 == ebp2:
            op2pop = 'ebp'

        if geto3 == esi2:
            op2pop = 'esi'

        if geto3 == edi2:
            op2pop = 'edi'

        if '0x50' in hexx:
            print reg + ' ' + op2

        if '0x51' in hexx:
            print reg + ' ' + op2

        if '0x52' in hexx:
            print reg + ' ' + op2

        if '0x53' in hexx:
            print reg + ' ' + op2

        if '0x54' in hexx:
            print reg + ' ' + op2

        if '0x55' in hexx:
            print reg + ' ' + op2

        if '0x56' in hexx:
            print reg + ' ' + op2

        if '0x57' in hexx:
            print reg + ' ' + op2



        if '0x58' in hexx:
            print regpop + ' ' + op2pop

        if '0x59' in hexx:
            print regpop + ' ' + op2pop

        if '0x5a' in hexx:
            print regpop + ' ' + op2pop

        if '0x5b' in hexx:
            print regpop + ' ' + op2pop

        if '0x5c' in hexx:
            print regpop + ' ' + op2pop

        if '0x5d' in hexx:
            print regpop + ' ' + op2pop

        if '0x5e' in hexx:
            print regpop + ' ' + op2pop

        if '0x5f' in hexx:
            print regpop + ' ' + op2pop

        i += 0
        continue

    if '0xb' in hexx:

        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hex1z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1z[:2]
        geto1 = hex1z[-6:-3]
        geto2 = hex1z[-3:]

        getmodplus1 = hex1z[:3]
        getmodplus2 = hex1z[:4]
        getmodplus3 = hex1z[:5]

        my_hexdata = hex(ord(fulldata[i - 0]))
        scale = 16
        num_of_bits = 8
        hex1zz = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmodz = hex1zz[:2]
        geto1z = hex1zz[-6:-3]
        geto2z = hex1zz[-3:]

        getmodplus1z = hex1zz[:3]
        getmodplus2z = hex1zz[:4]
        getmodplus3z = hex1zz[:5]

        if '10111' in getmodplus3:
            reg = 'MOV'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            movbytes1 = hex(ord(fulldata[i + 0]))
            movbytes2 = hex(ord(fulldata[i + 1]))
            movbytes3 = hex(ord(fulldata[i + 2]))
            movbytes4 = hex(ord(fulldata[i + 3]))
            movbytes_total = movbytes4 + movbytes3 + movbytes2 \
                + movbytes1
            movbytes_total = re.sub('0x', '', movbytes_total)

            print reg + ' ' + op1 + ', 0x' + movbytes_total
            i += 4
            continue

        if '00' in getmodz:
            if '101' in geto2z:
                reg = 'OR'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op2 + ', [0x' + addbytes_total + ']'
                i += 5
                continue
            else:

                reg = 'OR'
                if geto2 == eax:
                    op1 = 'eax'
                if geto2 == ecx:
                    op1 = 'ecx'
                if geto2 == edx:
                    op1 = 'edx'
                if geto2 == esp:
                    op1 = 'esp'
                if geto2 == ebp:
                    op1 = 'ebp'
                if geto2 == esi:
                    op1 = 'esi'
                if geto2 == edi:
                    op1 = 'edi'

                if geto3 == eax2:
                    op2 = 'eax'
                if geto3 == ecx2:
                    op2 = 'ecx'
                if geto3 == edx2:
                    op2 = 'edx'
                if geto3 == esp2:
                    op2 = 'esp'
                if geto3 == ebp2:
                    op2 = 'ebp'
                if geto3 == esi2:
                    op2 = 'esi'
                if geto3 == edi2:
                    op2 = 'edi'

                print reg + ' ' + op2 + ',[' + op1 + ']'
                i += 1
                continue

        if '01' in getmodz:
            reg = 'OR'
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 2
            continue

        if '10' in getmodz:
            reg = 'OR'
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 3
            continue

    if '0xc2' in hexx:
        reg = 'RETN'
        hex1 = bin(ord(fulldata[i]))
        hex1 = re.sub('0b', '', hex1)
        geto1 = hex1[-6:-3]
        geto2 = hex1[-3:]

        retbytes0 = hex(ord(fulldata[i + 0]))
        retbytes1 = hex(ord(fulldata[i + 1]))
        retbytes_total = retbytes1 + retbytes0
        retbytes_total = re.sub('0x', '', retbytes_total)



        print reg + ' 0x' + retbytes_total
        i += 2
        continue

    if '0xca' in hexx:
        reg = 'RETF'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)



        geto1 = hex1[-6:-3]
        geto2 = hex1[-3:]

        retbytes0 = hex(ord(fulldata[i + 0]))
        retbytes1 = hex(ord(fulldata[i + 1]))
        retbytes_total = retbytes1 + retbytes0
        retbytes_total = re.sub('0x', '', retbytes_total)



        print reg + ' 0x' + retbytes_total
        i += 2
        continue

    if '0x39' in hexx:
        reg = 'CMP'

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto1 = hex1[-6:-3]
        geto2 = hex1[-3:]

        if geto1 == eax:
            op1 = 'eax'

        if geto1 == ecx:
            op1 = 'ecx'

        if geto1 == edx:
            op1 = 'edx'

        if geto1 == esp:
            op1 = 'esp'

        if geto1 == ebp:
            op1 = 'ebp'

        if geto1 == esi:
            op1 = 'esi'

        if geto1 == edi:
            op1 = 'edi'

        if geto2 == eax:
            op2 = 'eax'

        if geto2 == ecx:
            op2 = 'ecx'

        if geto2 == edx:
            op2 = 'edx'

        if geto2 == esp:
            op2 = 'esp'

        if geto2 == ebp:
            op2 = 'ebp'

        if geto2 == esi:
            op2 = 'esi'

        if geto2 == edi:
            op2 = 'edi'

        if getmod == '01':
            nextbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nextbyte + '],' + op1
            i += 1
            continue

        if getmod == '10':
            nextbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nextbyte + '],' + op1
            i += 1
            continue

        if getmod == '00':
            print reg + ' [' + op2 + '],' + op1

        if getmod == '11':



            print reg + ' ' + op2 + ',' + op1
            i += 1
            continue
        else:



            i += 1
            continue

    if '0x74' in hexx:
        reg = 'JZ'
        Label = 'Label'

        if '74' in hexx:
            print reg + ' ' + Label
            i += 1
            continue

    if '0x4' in hexx:
        reg = 'INC'
        regDEC = 'DEC'
        hex1 = bin(ord(fulldata[i - 1]))
        hex1 = re.sub('0b', '', hex1)
        geto2 = hex1[-3:]
        geto3 = hex1[-4:]

        if geto2 == eax:
            op2 = 'eax'

        if geto2 == ecx:
            op2 = 'ecx'

        if geto2 == edx:
            op2 = 'edx'

        if geto2 == esp:
            op2 = 'esp'

        if geto2 == ebp:
            op2 = 'ebp'

        if geto2 == esi:
            op2 = 'esi'

        if geto2 == edi:
            op2 = 'edi'

        if geto3 == eax2:
            op2pop = 'eax'

        if geto3 == ecx2:
            op2pop = 'ecx'

        if geto3 in edx2:
            op2pop = 'edx'

        if geto3 == esp2:
            op2pop = 'esp'

        if geto3 == ebp2:
            op2pop = 'ebp'

        if geto3 == esi2:
            op2pop = 'esi'

        if geto3 == edi2:
            op2pop = 'edi'

        if '0x40' in hexx:
            print reg + ' ' + op2

        if '0x41' in hexx:
            print reg + ' ' + op2

        if '0x42' in hexx:
            print reg + ' ' + op2

        if '0x43' in hexx:
            print reg + ' ' + op2

        if '0x44' in hexx:
            print reg + ' ' + op2

        if '0x45' in hexx:
            print reg + ' ' + op2

        if '0x46' in hexx:
            print reg + ' ' + op2

        if '0x47' in hexx:
            print reg + ' ' + op2



        if '0x48' in hexx:
            print regDEC + ' ' + op2pop

        if '0x49' in hexx:
            print regDEC + ' ' + op2pop

        if '0x4a' in hexx:
            print regDEC + ' ' + op2pop

        if '0x4b' in hexx:
            print regDEC + ' ' + op2pop

        if '0x4c' in hexx:
            print regDEC + ' ' + op2pop

        if '0x4d' in hexx:
            print regDEC + ' ' + op2pop

        if '0x4e' in hexx:
            print regDEC + ' ' + op2pop

        if '0x4f' in hexx:
            print regDEC + ' ' + op2pop

        i += 0
        continue

    if '0x81' in hexx:
        reg = 'ADD'

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1z[:2]
        geto1 = hex1z[-6:-3]
        geto2 = hex1z[-3:]

        getmodplus1 = hex1z[:3]
        getmodplus2 = hex1z[:4]
        getmodplus3 = hex1z[:5]

        checkbytes = hex(ord(fulldata[i + 0]))

        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)



        if checkbytes == '0xd':
            reg = 'OR'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            addbytes1 = hex(ord(fulldata[i + 5]))
            addbytes2 = hex(ord(fulldata[i + 6]))
            addbytes3 = hex(ord(fulldata[i + 7]))
            addbytes4 = hex(ord(fulldata[i + 8]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total2 = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total1 + '],0x' \
                + addbytes_total2
            i += 9
            continue

        if checkbytes == '0x1d':
            reg = 'SBB'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            addbytes1 = hex(ord(fulldata[i + 5]))
            addbytes2 = hex(ord(fulldata[i + 6]))
            addbytes3 = hex(ord(fulldata[i + 7]))
            addbytes4 = hex(ord(fulldata[i + 8]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total2 = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total1 + '],0x' \
                + addbytes_total2
            i += 9
            continue

        if checkbytes == '0x3d':
            reg = 'CMP'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            addbytes1 = hex(ord(fulldata[i + 5]))
            addbytes2 = hex(ord(fulldata[i + 6]))
            addbytes3 = hex(ord(fulldata[i + 7]))
            addbytes4 = hex(ord(fulldata[i + 8]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total2 = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total1 + '],0x' \
                + addbytes_total2
            i += 9
            continue

        if getmodplus2 == '1111':
            reg = 'CMP'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' ' + op2 + ', 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '11011':
            reg = 'SBB'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' ' + op2 + ', 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '00111':
            reg = 'CMP'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [' + op2 + '], 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '00011':
            reg = 'SBB'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [' + op2 + '], 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '11001':
            reg = 'OR'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' ' + op2 + ', 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '00001':
            reg = 'OR'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [' + op2 + '], 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '01001':
            reg = 'OR'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 2]))
            addbytes2 = hex(ord(fulldata[i + 3]))
            addbytes3 = hex(ord(fulldata[i + 4]))
            addbytes4 = hex(ord(fulldata[i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 6
            continue

        if getmodplus3 == '01011':
            reg = 'SBB'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 2]))
            addbytes2 = hex(ord(fulldata[i + 3]))
            addbytes3 = hex(ord(fulldata[i + 4]))
            addbytes4 = hex(ord(fulldata[i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 6
            continue

        if getmodplus3 == '01111':
            reg = 'CMP'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 2]))
            addbytes2 = hex(ord(fulldata[i + 3]))
            addbytes3 = hex(ord(fulldata[i + 4]))
            addbytes4 = hex(ord(fulldata[i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 6
            continue

        if getmodplus3 == '10001':
            reg = 'OR'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            nbyte = hex(ord(fulldata[i + 1]))

            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 9
            continue

        if getmodplus3 == '10011':
            reg = 'SBB'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            nbyte = hex(ord(fulldata[i + 1]))

            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 9
            continue

        if getmodplus3 == '10111':
            reg = 'CMP'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            nbyte = hex(ord(fulldata[i + 1]))

            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 9
            continue

        if '100' in getmodplus1:
            nbyte = hex(ord(fulldata[i + 1]))



            if geto2 == '000':
                bytestoadd = '0'

            if geto2 == '001':
                bytestoadd = '1'

            if geto2 == '010':
                bytestoadd = '2'

            if geto2 == '011':
                bytestoadd = '3'

            if geto2 == '100':
                bytestoadd = '4'

            if geto2 == '101':
                bytestoadd = '5'

            if geto2 == '110':
                bytestoadd = '6'

            if geto2 == '111':
                bytestoadd = '7'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'



            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

                addbytes1 = hex(ord(fulldata[n + i + 2]))



                addbytes2 = hex(ord(fulldata[n + i + 3]))
                addbytes3 = hex(ord(fulldata[n + i + 4]))
                addbytes4 = hex(ord(fulldata[n + i + 5]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)



                print reg + ' [' + op2 + '+' + nbyte + '],0x' \
                    + addbytes_total
                i += 9
                continue

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            print reg + ' [' + op2 + '+' + nbyte + '],0x' \
                + addbytes_total
            i += 6
            continue

        if '101' in getmodplus1:
            nbyte = hex(ord(fulldata[i + 1]))



            if geto2 == '000':
                bytestoadd = '0'

            if geto2 == '001':
                bytestoadd = '1'

            if geto2 == '010':
                bytestoadd = '2'

            if geto2 == '011':
                bytestoadd = '3'

            if geto2 == '100':
                bytestoadd = '4'

            if geto2 == '101':
                bytestoadd = '5'

            if geto2 == '110':
                bytestoadd = '6'

            if geto2 == '111':
                bytestoadd = '7'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'



            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

                addbytes1 = hex(ord(fulldata[n + i + 2]))



                addbytes2 = hex(ord(fulldata[n + i + 3]))
                addbytes3 = hex(ord(fulldata[n + i + 4]))
                addbytes4 = hex(ord(fulldata[n + i + 5]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)



                print reg + ' [' + op2 + '+' + nbyte + '],0x' \
                    + addbytes_total
                i += 9
                continue

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            print reg + ' [' + op2 + '+' + nbyte + '],0x' \
                + addbytes_total
            i += 9
            continue

        if '010' in getmodplus1:

            nbyte = hex(ord(fulldata[i + 1]))



            if geto2 == '000':
                bytestoadd = '0'

            if geto2 == '001':
                bytestoadd = '1'

            if geto2 == '010':
                bytestoadd = '2'

            if geto2 == '011':
                bytestoadd = '3'

            if geto2 == '100':
                bytestoadd = '4'

            if geto2 == '101':
                bytestoadd = '5'

            if geto2 == '110':
                bytestoadd = '6'

            if geto2 == '111':
                bytestoadd = '7'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'



            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

                addbytes1 = hex(ord(fulldata[n + i + 2]))



                addbytes2 = hex(ord(fulldata[n + i + 3]))
                addbytes3 = hex(ord(fulldata[n + i + 4]))
                addbytes4 = hex(ord(fulldata[n + i + 5]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)



                print reg + ' [' + op2 + '+' + nbyte + '],0x' \
                    + addbytes_total
                i += 9
                continue

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            print reg + ' [' + op2 + '+' + nbyte + '],0x' \
                + addbytes_total
            i += 6
            continue

        if checkbytes == '0x5':
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            addbytes1 = hex(ord(fulldata[i + 5]))
            addbytes2 = hex(ord(fulldata[i + 6]))
            addbytes3 = hex(ord(fulldata[i + 7]))
            addbytes4 = hex(ord(fulldata[i + 8]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total2 = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total1 + '],0x' \
                + addbytes_total2
            i += 9
            continue

        if getmodplus1 == '011':
            reg = 'AND'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'



            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

            nbyte = hex(ord(fulldata[i + 1]))

            addbytes1 = hex(ord(fulldata[i + 2]))
            addbytes2 = hex(ord(fulldata[i + 3]))
            addbytes3 = hex(ord(fulldata[i + 4]))
            addbytes4 = hex(ord(fulldata[i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)
            print reg + ' [' + op2 + '+' + nbyte + '],0x' \
                + addbytes_total2
            i += 6
            continue

        if getmodplus1 == '111':
            reg = 'AND'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)
            print reg + ' ' + op2 + ',0x' + addbytes_total2
            i += 5
            continue

        if getmodplus1 == '001':
            reg = 'AND'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total1 = re.sub('0x', '', addbytes_total)

                addbytes1 = hex(ord(fulldata[i + 5]))
                addbytes2 = hex(ord(fulldata[i + 6]))
                addbytes3 = hex(ord(fulldata[i + 7]))
                addbytes4 = hex(ord(fulldata[i + 8]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total2 = re.sub('0x', '', addbytes_total)

                print reg + ' [0x' + addbytes_total1 + '],0x' \
                    + addbytes_total2
                i += 9
                continue

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)
            print reg + ' ' + op2 + ',[0x' + addbytes_total2 + ']'
            i += 5
            continue

        if getmod == '11':
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            if '0x81' in hexx:
                print reg + ' ' + op2 + ',0x' + addbytes_total
                i += 5
                continue





        if getmodplus2 == '0000':

            hex1 = bin(ord(fulldata[i]))
            hex1 = re.sub('0b', '', hex1)

            if hex1 == '0':
                op2 = 'eax'

            if hex1 == '1':
                op2 = 'ecx'

            if hex1 == '2':
                op2 = 'edx'

            if hex1 == '3':
                op2 = 'ebx'

            if hex1 == '4':
                op2 = 'esp'

            if hex1 == '5':
                op2 = 'ebp'

            if hex1 == '6':
                op2 = 'esi'

            if hex1 == '7':
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            if '0x81' in hexx:
                print reg + ' [' + op2 + '],0x' + addbytes_total
                i += 5
                continue



        if getmod == '01':

            hex1 = bin(ord(fulldata[i]))
            hex1 = re.sub('0b', '', hex1)
            geto2 = hex1[-3:]

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'



            hex0 = bin(ord(fulldata[i + 1]))
            hex0 = re.sub('0b', '', hex0)
            geto2 = hex1[-3:]

            if hex0 == '000':
                bytestoadd = '0'

            if hex0 == '001':
                bytestoadd = '1'

            if hex0 == '010':
                bytestoadd = '2'

            if hex0 == '011':
                bytestoadd = '3'

            if hex0 == '100':
                bytestoadd = '4'

            if hex0 == '101':
                bytestoadd = '5'

            if hex0 == '110':
                bytestoadd = '6'

            if hex0 == '111':
                bytestoadd = '7'



            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

                addbytes1 = hex(ord(fulldata[n + i + 2]))



                addbytes2 = hex(ord(fulldata[n + i + 3]))
                addbytes3 = hex(ord(fulldata[n + i + 4]))
                addbytes4 = hex(ord(fulldata[n + i + 5]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)



                print reg + ' [' + op2 + '+0x' + bytestoadd + '],0x' \
                    + addbytes_total
                i += 9
                continue

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            print reg + ' [' + op2 + '+0x' + bytestoadd + '],0x' \
                + addbytes_total
            i += 6
            continue

    if '0x5' in hexx:
        reg = 'ADD'
        hex1 = bin(ord(fulldata[i]))
        hex1 = re.sub('0b', '', hex1)
        addbytes1 = hex(ord(fulldata[i + 0]))
        addbytes2 = hex(ord(fulldata[i + 1]))
        addbytes3 = hex(ord(fulldata[i + 2]))
        addbytes4 = hex(ord(fulldata[i + 3]))
        addbytes_total = addbytes4 + addbytes3 + addbytes2 + addbytes1
        addbytes_total = re.sub('0x', '', addbytes_total)

        if '0x5' in hexx:
            print reg + ' eax,0x' + addbytes_total
            i += 4
            continue

    if '0x21' in hexx:
        reg = 'AND'

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        if '11' in getmod:
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' ' + op2 + ',' + op1
            i += 1
            continue

        if '00' in getmod:
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' [' + op2 + '],' + op1
            i += 1
            continue

        if '01' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '],' + op1
            i += 2
            continue

        if '10' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '],' + op1
            i += 2
            continue

    if '0x23' in hexx:



        reg = 'AND'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        if '00' in getmod:

            if geto3 == '101':
                my_hexdata = hex(ord(fulldata[i]))
                scale = 16
                num_of_bits = 8
                hex1 = bin(int(my_hexdata,
                           scale))[2:].zfill(num_of_bits)
                geto2 = hex1[-6:-3]



                if geto2 == eax:
                    op1 = 'eax'
                if geto2 == ecx:
                    op1 = 'ecx'
                if geto2 == edx:
                    op1 = 'edx'
                if geto2 == esp:
                    op1 = 'esp'
                if geto2 == ebp:
                    op1 = 'ebp'
                if geto2 == esi:
                    op1 = 'esi'
                if geto2 == edi:
                    op1 = 'edi'

                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op1 + ', [0x' + addbytes_total + ']'
                i += 5
                continue

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'

            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' ' + op1 + ',[' + op2 + ']'
            i += 1
            continue

        if '01' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' ' + op1 + ', [' + op2 + '+' + nbyte + ']'



            i += 2
            continue

        if '10' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))






            print reg + ' ' + op1 + ', [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

    if '0xe8' in hexx:

        reg = 'CALL'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        callbinary = hex1
        print reg + ' Hex:' + my_hexdata + ' Bin:' + callbinary
        i += 4
        continue

    if '0xff' in hexx:
        reg = 'CALL'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]



        geto2 = hex1[-3:]

        getmodplus1 = hex1[:8]

        getmodplus2 = hex1[:4]
        getmodplus3 = hex1[:5]



        if '00100101' in hex1:
            reg = 'JMP'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' eax, [0x' + addbytes_total + ']'
            i += 5
            continue

        if '00001101' in hex1:
            reg = 'DEC'
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)





            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '00000101' in hex1:
            reg = 'INC'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '00110101' in hex1:
            reg = 'PUSH'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '11000' in getmodplus3:
            reg = 'INC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' ' + op1
            i += 1
            continue

        if '11001' in getmodplus3:
            reg = 'DEC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' ' + op1
            i += 1
            continue

        if '00001' in getmodplus3:
            reg = 'DEC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']'
            i += 1
            continue

        if '00000' in getmodplus3:
            reg = 'INC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'
            print reg + ' [' + op1 + ']'
            i += 1
            continue

        if '01001' in getmodplus3:
            reg = 'DEC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '10001' in getmodplus3:
            reg = 'DEC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '00010101' in getmodplus1:
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '01000' in getmodplus3:
            reg = 'INC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '10000' in getmodplus3:
            reg = 'INC'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '11100' in getmodplus3:
            reg = 'JMP'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' ' + op1
            i += 1
            continue

        if '00100' in getmodplus3:
            reg = 'JMP'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']'
            i += 1
            continue

        if '01100' in getmodplus3:
            reg = 'JMP'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '10100' in getmodplus3:
            reg = 'JMP'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '11110' in getmodplus3:
            reg = 'PUSH'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' ' + op1
            i += 1
            continue

        if '00110' in getmodplus3:
            reg = 'PUSH'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']'
            i += 1
            continue

        if '01110' in getmodplus3:
            reg = 'PUSH'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '10110' in getmodplus3:
            reg = 'PUSH'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '11' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' ' + op1
            i += 1
            continue

        if '00' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']'
            i += 1
            continue

        if '01' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '10' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

    if '0x3d' in hexx:
        reg = 'CMP'
        my_hexdata = hex(ord(fulldata[i]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        getmodplus1 = hex1[:8]

        if '000' in geto2:
            addbytes1 = hex(ord(fulldata[i + 0]))
            addbytes2 = hex(ord(fulldata[i + 1]))
            addbytes3 = hex(ord(fulldata[i + 2]))
            addbytes4 = hex(ord(fulldata[i + 3]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' eax, [0x' + addbytes_total + ']'
            i += 4
            continue

    if '0x3b' in hexx:



        reg = 'CMP'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        if '00' in getmod:

            if geto3 == '101':
                my_hexdata = hex(ord(fulldata[i]))
                scale = 16
                num_of_bits = 8
                hex1 = bin(int(my_hexdata,
                           scale))[2:].zfill(num_of_bits)
                geto2 = hex1[-6:-3]



                if geto2 == eax:
                    op1 = 'eax'
                if geto2 == ecx:
                    op1 = 'ecx'
                if geto2 == edx:
                    op1 = 'edx'
                if geto2 == esp:
                    op1 = 'esp'
                if geto2 == ebp:
                    op1 = 'ebp'
                if geto2 == esi:
                    op1 = 'esi'
                if geto2 == edi:
                    op1 = 'edi'

                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op1 + ', [0x' + addbytes_total + ']'
                i += 5
                continue

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'

            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' ' + op1 + ',[' + op2 + ']'
            i += 1
            continue

        if '01' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' ' + op1 + ', [' + op2 + '+' + nbyte + ']'



            i += 2
            continue

        if '10' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))






            print reg + ' ' + op1 + ', [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

    if '0xf7' in hexx:
        reg = 'IDIV'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]



        geto2 = hex1[-3:]

        getmodplus1 = hex1[:8]

        getmodplus2 = hex1[:4]
        getmodplus3 = hex1[:5]



        checkbytes = hex(ord(fulldata[i + 0]))

        if '00100101' in getmodplus1:
            reg = 'MUL'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '00010101' in getmodplus1:
            reg = 'NOT'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '00011101' in getmodplus1:
            reg = 'NEG'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '00111101' in hex1:
            reg = 'IDIV'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '11111' in getmodplus3:

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' ' + op2
            i += 1
            continue

        if '11100' in getmodplus3:
            reg = 'MUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' ' + op2
            i += 1
            continue

        if '11010' in getmodplus3:
            reg = 'NOT'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' ' + op2
            i += 1
            continue

        if '00111' in getmodplus3:

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' [' + op2 + ']'
            i += 1
            continue

        if '00100' in getmodplus3:
            reg = 'MUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' [' + op2 + ']'
            i += 1
            continue

        if '00010' in getmodplus3:
            reg = 'NOT'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' [' + op2 + ']'
            i += 1
            continue

        if '01100' in getmodplus3:
            reg = 'MUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '10100' in getmodplus3:
            reg = 'MUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '01111' in getmodplus3:

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '01010' in getmodplus3:
            reg = 'NOT'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '10010' in getmodplus3:
            reg = 'NOT'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '10111' in getmodplus3:

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '11101' in getmodplus3:
            reg = 'IMUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' eax, ' + op2
            i += 1
            continue

        if '00101' in getmodplus3:
            reg = 'IMUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            print reg + ' eax, [' + op2 + ']'
            i += 1
            continue

        if '01101' in getmodplus3:
            reg = 'IMUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' eax, [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '10101' in getmodplus3:
            reg = 'IMUL'
            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' eax, [' + op2 + '+' + nbyte + ']'
            i += 2
            continue

        if '11011' in getmodplus3:
            reg = 'NEG'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' ' + op1
            i += 1
            continue

        if '00011' in getmodplus3:
            reg = 'NEG'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']'
            i += 1
            continue

        if '01011' in getmodplus3:
            reg = 'NEG'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '10011' in getmodplus3:
            reg = 'NEG'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if checkbytes == '0x5':
            reg = 'TEST'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            addbytes1 = hex(ord(fulldata[i + 5]))
            addbytes2 = hex(ord(fulldata[i + 6]))
            addbytes3 = hex(ord(fulldata[i + 7]))
            addbytes4 = hex(ord(fulldata[i + 8]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total2 = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total1 + '], 0x' \
                + addbytes_total2
            i += 9
            continue

        if getmodplus3 == '11000':
            reg = 'TEST'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' ' + op2 + ', 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '00000':
            reg = 'TEST'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [' + op2 + '], 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '01000':
            reg = 'TEST'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 2]))
            addbytes2 = hex(ord(fulldata[i + 3]))
            addbytes3 = hex(ord(fulldata[i + 4]))
            addbytes4 = hex(ord(fulldata[i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            nbyte = hex(ord(fulldata[i + 1]))



            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 6
            continue

        if getmodplus3 == '10000':
            reg = 'TEST'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            nbyte = hex(ord(fulldata[i + 1]))

            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 9
            continue

    if '0xf' in hexx:
        reg = 'IMUL'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]
        getmodplus1 = hex1[:8]
        getmodplus2 = hex1[:4]
        getmodplus3 = hex1[:5]

        if '10101111' in hex1:
            my_hexdata = hex(ord(fulldata[i + 1]))
            scale = 16
            num_of_bits = 8
            hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            getmod = hex1[:2]
            geto2 = hex1[-6:-3]
            geto3 = hex1[-3:]
            getmodplus1 = hex1[:8]
            getmodplus2 = hex1[:4]
            getmodplus3 = hex1[:5]

            if '00' in getmod:
                if '101' in geto3:
                    reg = 'IMUL'

                    if geto2 == eax:
                        op2 = 'eax'
                    if geto2 == ecx:
                        op2 = 'ecx'
                    if geto2 == edx:
                        op2 = 'edx'
                    if geto2 == esp:
                        op2 = 'esp'
                    if geto2 == ebp:
                        op2 = 'ebp'
                    if geto2 == esi:
                        op2 = 'esi'
                    if geto2 == edi:
                        op2 = 'edi'
                    addbytes1 = hex(ord(fulldata[i + 2]))
                    addbytes2 = hex(ord(fulldata[i + 3]))
                    addbytes3 = hex(ord(fulldata[i + 4]))
                    addbytes4 = hex(ord(fulldata[i + 5]))
                    addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                        + addbytes1
                    addbytes_total = re.sub('0x', '', addbytes_total)

                    print reg + ' ' + op2 + ', [0x' + addbytes_total \
                        + ']'
                    i += 6
                    continue

                my_hexdata = hex(ord(fulldata[i + 1]))
                scale = 16
                num_of_bits = 8
                hex2 = bin(int(my_hexdata,
                           scale))[2:].zfill(num_of_bits)

                geto2 = hex2[-6:-3]
                geto3 = hex2[-3:]
                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'

                if geto3 == eax2:
                    op2pop = 'eax'
                if geto3 == ecx2:
                    op2pop = 'ecx'
                if geto3 == edx2:
                    op2pop = 'edx'
                if geto3 == esp2:
                    op2pop = 'esp'
                if geto3 == ebp2:
                    op2pop = 'ebp'
                if geto3 == esi2:
                    op2pop = 'esi'
                if geto3 == edi2:
                    op2pop = 'edi'

                print reg + ' ' + op2 + ', [' + op2pop + ']'
                i += 2
                continue

            if '01' in getmod:
                my_hexdata = hex(ord(fulldata[i + 1]))
                scale = 16
                num_of_bits = 8
                hex2 = bin(int(my_hexdata,
                           scale))[2:].zfill(num_of_bits)

                geto2 = hex2[-6:-3]
                geto3 = hex2[-3:]
                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'

                if geto3 == eax2:
                    op2pop = 'eax'
                if geto3 == ecx2:
                    op2pop = 'ecx'
                if geto3 == edx2:
                    op2pop = 'edx'
                if geto3 == esp2:
                    op2pop = 'esp'
                if geto3 == ebp2:
                    op2pop = 'ebp'
                if geto3 == esi2:
                    op2pop = 'esi'
                if geto3 == edi2:
                    op2pop = 'edi'

                nbyte = hex(ord(fulldata[i + 2]))
                print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte \
                    + ']'
                i += 3
                continue

            if '10' in getmod:
                my_hexdata = hex(ord(fulldata[i + 1]))
                scale = 16
                num_of_bits = 8
                hex2 = bin(int(my_hexdata,
                           scale))[2:].zfill(num_of_bits)

                geto2 = hex2[-6:-3]
                geto3 = hex2[-3:]
                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'

                if geto3 == eax2:
                    op2pop = 'eax'
                if geto3 == ecx2:
                    op2pop = 'ecx'
                if geto3 == edx2:
                    op2pop = 'edx'
                if geto3 == esp2:
                    op2pop = 'esp'
                if geto3 == ebp2:
                    op2pop = 'ebp'
                if geto3 == esi2:
                    op2pop = 'esi'
                if geto3 == edi2:
                    op2pop = 'edi'

                nbyte = hex(ord(fulldata[i + 2]))
                print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte \
                    + ']'
                i += 3
                continue

    if '0x69' in hexx:
        reg = 'IMUL'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto1 = hex1[-6:-3]
        geto2 = hex1[-3:]
        getmodplus1 = hex1[:8]
        getmodplus2 = hex1[:4]
        getmodplus3 = hex1[:5]

        if geto1 == eax:
            op1 = 'eax'
        if geto1 == ecx:
            op1 = 'ecx'
        if geto1 == edx:
            op1 = 'edx'
        if geto1 == esp:
            op1 = 'esp'
        if geto1 == ebp:
            op1 = 'ebp'
        if geto1 == esi:
            op1 = 'esi'
        if geto1 == edi:
            op1 = 'edi'
        if geto2 == eax:
            op2 = 'eax'
        if geto2 == ecx:
            op2 = 'ecx'
        if geto2 == edx:
            op2 = 'edx'
        if geto2 == esp:
            op2 = 'esp'
        if geto2 == ebp:
            op2 = 'ebp'
        if geto2 in esi:
            op2 = 'esi'
        if geto2 in edi:
            op2 = 'edi'

        if '00' in getmod:
            if '00' in getmod:
                if '101' in geto2:
                    reg = 'IMUL'

                    if geto1 == eax:
                        op2 = 'eax'
                    if geto1 == ecx:
                        op2 = 'ecx'
                    if geto1 == edx:
                        op2 = 'edx'
                    if geto1 == esp:
                        op2 = 'esp'
                    if geto1 == ebp:
                        op2 = 'ebp'
                    if geto1 == esi:
                        op2 = 'esi'
                    if geto1 == edi:
                        op2 = 'edi'
                    addbytes1 = hex(ord(fulldata[i + 1]))
                    addbytes2 = hex(ord(fulldata[i + 2]))
                    addbytes3 = hex(ord(fulldata[i + 3]))
                    addbytes4 = hex(ord(fulldata[i + 4]))
                    addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                        + addbytes1
                    addbytes_total = re.sub('0x', '', addbytes_total)

                    addbytes11 = hex(ord(fulldata[i + 5]))
                    addbytes22 = hex(ord(fulldata[i + 6]))
                    addbytes33 = hex(ord(fulldata[i + 7]))
                    addbytes44 = hex(ord(fulldata[i + 8]))
                    addbytes_total2 = addbytes44 + addbytes33 \
                        + addbytes22 + addbytes11
                    addbytes_total2 = re.sub('0x', '', addbytes_total2)

                    print reg + ' ' + op2 + ', [0x' + addbytes_total \
                        + '], 0x' + addbytes_total2
                    i += 9
                    continue

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' ' + op1 + ', [' + op2 + '], 0x' \
                + addbytes_total
            i += 5
            continue

        if '01' in getmod:

            addbytes1 = hex(ord(fulldata[i + 2]))
            addbytes2 = hex(ord(fulldata[i + 3]))
            addbytes3 = hex(ord(fulldata[i + 4]))
            addbytes4 = hex(ord(fulldata[i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op1 + ', [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 6
            continue

        if '10' in getmod:

            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))



            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1
            if nulls == '0x0':



                n += 1

            addbytes1 = hex(ord(fulldata[n + i + 2]))



            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)



            nbyte = hex(ord(fulldata[i + 1]))

            print reg + ' ' + op1 + ', [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 9
            continue

    if '0xe9' in hexx:
        reg = 'JMP'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        callbinary = hex1
        addbytes1 = hex(ord(fulldata[i + 0]))
        addbytes2 = hex(ord(fulldata[i + 1]))
        addbytes3 = hex(ord(fulldata[i + 2]))
        addbytes_total = addbytes3 + addbytes2 + addbytes1
        addbytes_total = re.sub('0x', '', addbytes_total)
        print reg + ' Offset: 0x' + addbytes_total
        i += 4
        continue
    if '0xeb' in hexx:
        reg = 'JMP'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        callbinary = hex1
        addbytes1 = hex(ord(fulldata[i + 0]))
        addbytes_total = re.sub('0x', '', addbytes_total)
        print reg + ' Offset: ' + addbytes1
        i += 1
        continue

    if '0xf' in hexx:
        reg = 'jz'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        if '0xf2' in hexx:
            reg = 'REPNE'
            print reg + ' [edi], [esi]'
            i += 1
            continue

        if '10' in getmod:

            callbinary = hex1
            addbytes1 = hex(ord(fulldata[i + 0]))
            addbytes2 = hex(ord(fulldata[i + 1]))
            addbytes3 = hex(ord(fulldata[i + 2]))
            addbytes_total = addbytes3 + addbytes2 + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)
            print reg + ' Offset_' + addbytes_total
            i += 5
            continue

    if '0x75' in hexx:
        reg = 'jz'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        print reg + ' Offset_' + hexx
        i += 1
        continue

    if '0x8d' in hexx:
        reg = 'LEA'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]
        getmodplus1 = hex1[:8]
        getmodplus2 = hex1[:4]
        getmodplus3 = hex1[:5]

        if geto1 == eax:
            op1 = 'eax'
        if geto1 == ecx:
            op1 = 'ecx'
        if geto1 == edx:
            op1 = 'edx'
        if geto1 == esp:
            op1 = 'esp'
        if geto1 == ebp:
            op1 = 'ebp'
        if geto1 == esi:
            op1 = 'esi'
        if geto1 == edi:
            op1 = 'edi'
        if geto2 == eax:
            op2 = 'eax'
        if geto2 == ecx:
            op2 = 'ecx'
        if geto2 == edx:
            op2 = 'edx'
        if geto2 == esp:
            op2 = 'esp'
        if geto2 == ebp:
            op2 = 'ebp'
        if geto2 in esi:
            op2 = 'esi'
        if geto2 in edi:
            op2 = 'edi'

        if '00' in getmod:
            if '101' in geto3:
                reg = 'LEA'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op2 + ', [0x' + addbytes_total + ']'
                i += 5
                continue
            else:

                print reg + ' ' + op1 + ', [' + op2 + ']'
                i += 1
                continue

        if '01' in getmod:
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 2
            continue

        if '10' in getmod:
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 3
            continue

            if '101' in geto3:
                reg = 'LEA'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 2]))
                addbytes2 = hex(ord(fulldata[i + 3]))
                addbytes3 = hex(ord(fulldata[i + 4]))
                addbytes4 = hex(ord(fulldata[i + 5]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op2 + ', [0x' + addbytes_total + ']'
                i += 6

            my_hexdata = hex(ord(fulldata[i + 1]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            print reg + ' ' + op2 + ', [' + op2pop + ']'
            i += 2
            continue

    if '0xc7' in hexx:
        reg = 'MOV'

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmod = hex1z[:2]
        geto1 = hex1z[-6:-3]
        geto2 = hex1z[-3:]
        getmodplus1 = hex1z[:3]
        getmodplus2 = hex1z[:4]
        getmodplus3 = hex1z[:5]

        checkbytes = hex(ord(fulldata[i + 0]))

        if hex1z == '00000101':
            reg = 'MOV'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            addbytes1 = hex(ord(fulldata[i + 5]))
            addbytes2 = hex(ord(fulldata[i + 6]))
            addbytes3 = hex(ord(fulldata[i + 7]))
            addbytes4 = hex(ord(fulldata[i + 8]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total2 = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total1 + '],0x' \
                + addbytes_total2
            i += 9
            continue

        if getmodplus3 == '00000':
            reg = 'MOV'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [' + op2 + '], 0x' + addbytes_total
            i += 5
            continue

        if getmodplus3 == '01000':
            reg = 'MOV'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 in esi:
                op2 = 'esi'

            if geto2 in edi:
                op2 = 'edi'

            addbytes1 = hex(ord(fulldata[i + 2]))
            addbytes2 = hex(ord(fulldata[i + 3]))
            addbytes3 = hex(ord(fulldata[i + 4]))
            addbytes4 = hex(ord(fulldata[i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 6
            continue

        if getmodplus3 == '10000':
            reg = 'MOV'

            if geto2 == eax:
                op2 = 'eax'

            if geto2 == ecx:
                op2 = 'ecx'

            if geto2 == edx:
                op2 = 'edx'

            if geto2 == esp:
                op2 = 'esp'

            if geto2 == ebp:
                op2 = 'ebp'

            if geto2 == esi:
                op2 = 'esi'

            if geto2 == edi:
                op2 = 'edi'

            n += 0
            nulls = hex(ord(fulldata[n + i + 2]))
            if nulls == '0x0':
                n += 1
            if nulls == '0x0':
                n += 1
            if nulls == '0x0':
                n += 1

            addbytes1 = hex(ord(fulldata[n + i + 2]))
            addbytes2 = hex(ord(fulldata[n + i + 3]))
            addbytes3 = hex(ord(fulldata[n + i + 4]))
            addbytes4 = hex(ord(fulldata[n + i + 5]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)
            nbyte = hex(ord(fulldata[i + 1]))

            print reg + ' [' + op2 + '+' + nbyte + '], 0x' \
                + addbytes_total
            i += 9
            continue

    if '0x89' in hexx:
        reg = 'MOV'

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        if '11' in getmod:
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'
            print reg + ' ' + op2 + ', ' + op1
            i += 1
            continue

        if '00' in getmod:
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' [' + op2 + '], ' + op1
            i += 1
            continue

        if '01' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

        if '10' in getmod:

            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

    if '0x8b' in hexx:
        reg = 'MOV'
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto1 = hex1[-6:-3]
        geto2 = hex1[-3:]
        getmodplus1 = hex1[:8]
        getmodplus2 = hex1[:4]
        getmodplus3 = hex1[:5]

        if geto1 == eax:
            op1 = 'eax'
        if geto1 == ecx:
            op1 = 'ecx'
        if geto1 == edx:
            op1 = 'edx'
        if geto1 == esp:
            op1 = 'esp'
        if geto1 == ebp:
            op1 = 'ebp'
        if geto1 == esi:
            op1 = 'esi'
        if geto1 == edi:
            op1 = 'edi'
        if geto2 == eax:
            op2 = 'eax'
        if geto2 == ecx:
            op2 = 'ecx'
        if geto2 == edx:
            op2 = 'edx'
        if geto2 == esp:
            op2 = 'esp'
        if geto2 == ebp:
            op2 = 'ebp'
        if geto2 in esi:
            op2 = 'esi'
        if geto2 in edi:
            op2 = 'edi'

        if '00' in getmod:
            if '101' in geto2:
                reg = 'MOV'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op2 + ', [0x' + addbytes_total + ']'
                i += 5
                continue
            else:

                print reg + ' ' + op1 + ', [' + op2 + ']'
                i += 1
                continue

        if '01' in getmod:
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            op2pop = "eax" #null value /not used.
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax:
                op2pop = 'eax'
            if geto3 == ecx:
                op2pop = 'ecx'
            if geto3 == edx:
                op2pop = 'edx'
            if geto3 == esp:
                op2pop = 'esp'
            if geto3 == ebp:
                op2pop = 'ebp'
            if geto3 == esi:
                op2pop = 'esi'
            if geto3 == edi:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg+" "+op2+", ["+op2pop+"+"+nbyte+"]"
            i += 2
            continue

        if '10' in getmod:
            my_hexdata = hex(ord(fulldata[i + 0]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' ' + op2 + ', [' + op2pop + '+' + nbyte + ']'
            i += 3
            continue

            if '101' in geto3:
                reg = 'MOV'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 2]))
                addbytes2 = hex(ord(fulldata[i + 3]))
                addbytes3 = hex(ord(fulldata[i + 4]))
                addbytes4 = hex(ord(fulldata[i + 5]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)

                print reg + ' ' + op2 + ', [0x' + addbytes_total + ']'
                i += 6

            my_hexdata = hex(ord(fulldata[i + 1]))
            scale = 16
            num_of_bits = 8
            hex2 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

            geto2 = hex2[-6:-3]
            geto3 = hex2[-3:]
            if geto2 == eax:
                op2 = 'eax'
            if geto2 == ecx:
                op2 = 'ecx'
            if geto2 == edx:
                op2 = 'edx'
            if geto2 == esp:
                op2 = 'esp'
            if geto2 == ebp:
                op2 = 'ebp'
            if geto2 == esi:
                op2 = 'esi'
            if geto2 == edi:
                op2 = 'edi'

            if geto3 == eax2:
                op2pop = 'eax'
            if geto3 == ecx2:
                op2pop = 'ecx'
            if geto3 == edx2:
                op2pop = 'edx'
            if geto3 == esp2:
                op2pop = 'esp'
            if geto3 == ebp2:
                op2pop = 'ebp'
            if geto3 == esi2:
                op2pop = 'esi'
            if geto3 == edi2:
                op2pop = 'edi'

            print reg + ' ' + op2 + ', [' + op2pop + ']'
            i += 2
            continue

    if '0xd' in hexx:
        reg = 'OR'
        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hex1z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmod = hex1z[:2]
        geto1 = hex1z[-6:-3]
        geto2 = hex1z[-3:]
        getmodplus1 = hex1z[:3]
        getmodplus2 = hex1z[:4]
        getmodplus3 = hex1z[:5]
        my_hexdata = hex(ord(fulldata[i - 0]))
        scale = 16
        num_of_bits = 8
        hex1zz = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmodz = hex1zz[:2]
        geto1z = hex1zz[-6:-3]
        geto2z = hex1zz[-3:]
        getmodplus1z = hex1zz[:3]
        getmodplus2z = hex1zz[:4]
        getmodplus3z = hex1zz[:5]
        checkbytes = hex(ord(fulldata[i + 0]))

        if hex1z == '00001101':
            reg = 'OR'
            addbytes1 = hex(ord(fulldata[i + 0]))
            addbytes2 = hex(ord(fulldata[i + 1]))
            addbytes3 = hex(ord(fulldata[i + 2]))
            addbytes4 = hex(ord(fulldata[i + 3]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            print reg + ' eax, 0x' + addbytes_total1
            i += 4
            continue

        if '11100' in getmodplus3z:
            reg = 'SHL'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            print reg + ' ' + op1 + ', 1'
            i += 1
            continue

        if '00100' in getmodplus3z:
            reg = 'SHL'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']' + ', 1'
            i += 1
            continue

        if '01100' in getmodplus3z:
            reg = 'SHL'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']' + ', 1'
            i += 2
            continue

        if '10100' in getmodplus3z:
            reg = 'SHL'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']' + ', 1'
            i += 2
            continue

        if '11111' in getmodplus3z:
            reg = 'SAR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            print reg + ' ' + op1 + ', 1'
            i += 1
            continue

        if '00111' in getmodplus3z:
            reg = 'SAR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']' + ', 1'
            i += 1
            continue

        if '01111' in getmodplus3z:
            reg = 'SAR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']' + ', 1'
            i += 2
            continue

        if '10111' in getmodplus3z:
            reg = 'SAR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']' + ', 1'
            i += 2
            continue

        if '11101' in getmodplus3z:
            reg = 'SHR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            print reg + ' ' + op1 + ', 1'
            i += 1
            continue

        if '00101' in getmodplus3z:
            reg = 'SHR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']' + ', 1'
            i += 1
            continue

        if '01101' in getmodplus3z:
            reg = 'SHR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']' + ', 1'
            i += 2
            continue

        if '10101' in getmodplus3z:
            reg = 'SHR'
            if geto2z == eax:
                op1 = 'eax'
            if geto2z == ecx:
                op1 = 'ecx'
            if geto2z == edx:
                op1 = 'edx'
            if geto2z == esp:
                op1 = 'esp'
            if geto2z == ebp:
                op1 = 'ebp'
            if geto2z == esi:
                op1 = 'esi'
            if geto2z == edi:
                op1 = 'edi'
            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']' + ', 1'
            i += 2
            continue

    if '0xcb' in hexx:
        reg = 'RETF'
        print reg
        continue

    if '0xc3' in hexx:
        reg = 'RETN'
        print reg
        continue

    if '0xa5' in hexx:
        reg = 'MOVS'
        print reg + ' [edi], [esi]'
        continue

    if '0xa9' in hexx:
        reg = 'TEST'
        addbytes1 = hex(ord(fulldata[i + 0]))
        addbytes2 = hex(ord(fulldata[i + 1]))
        addbytes3 = hex(ord(fulldata[i + 2]))
        addbytes4 = hex(ord(fulldata[i + 3]))
        addbytes_total = addbytes4 + addbytes3 + addbytes2 + addbytes1
        addbytes_total = re.sub('0x', '', addbytes_total)
        print reg + ' eax, 0x' + addbytes_total
        i += 4
        continue

    if '0x9' in hexx:
        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hexcurrent = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]
        reg = 'NOP'

        if '10010000' in hexcurrent:
            print reg
            continue

        if '11' in getmod:
            reg = 'OR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' ' + op2 + ', ' + op1
            i += 1
            continue

        if '00' in getmod:
            reg = 'OR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'
            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'
            print reg + ' [' + op2 + '], ' + op1
            i += 1
            continue

        if '01' in getmod:
            reg = 'OR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'
            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'
            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

        if '10' in getmod:
            reg = 'OR'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

    if '0x8f' in hexx:
        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]
        getmodplus1 = hex1[:8]
        getmodplus2 = hex1[:4]
        getmodplus3 = hex1[:5]

        if '00000101' in hex1:
            reg = 'POP'
            addbytes1 = hex(ord(fulldata[i + 1]))
            addbytes2 = hex(ord(fulldata[i + 2]))
            addbytes3 = hex(ord(fulldata[i + 3]))
            addbytes4 = hex(ord(fulldata[i + 4]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total = re.sub('0x', '', addbytes_total)

            print reg + ' [0x' + addbytes_total + ']'
            i += 5
            continue

        if '11000' in hex1:
            reg = 'POP'
            if geto3 == eax:
                op1 = 'eax'
            if geto3 == ecx:
                op1 = 'ecx'
            if geto3 == edx:
                op1 = 'edx'
            if geto3 == esp:
                op1 = 'esp'
            if geto3 == ebp:
                op1 = 'ebp'
            if geto3 == esi:
                op1 = 'esi'
            if geto3 == edi:
                op1 = 'edi'

            print reg + ' ' + op1
            i += 1
            continue

        if '00000' in getmodplus3:
            reg = 'POP'
            if geto3 == eax:
                op1 = 'eax'
            if geto3 == ecx:
                op1 = 'ecx'
            if geto3 == edx:
                op1 = 'edx'
            if geto3 == esp:
                op1 = 'esp'
            if geto3 == ebp:
                op1 = 'ebp'
            if geto3 == esi:
                op1 = 'esi'
            if geto3 == edi:
                op1 = 'edi'

            print reg + ' [' + op1 + ']'
            i += 1
            continue

        if '01000' in getmodplus3:
            reg = 'POP'
            if geto3 == eax:
                op1 = 'eax'
            if geto3 == ecx:
                op1 = 'ecx'
            if geto3 == edx:
                op1 = 'edx'
            if geto3 == esp:
                op1 = 'esp'
            if geto3 == ebp:
                op1 = 'ebp'
            if geto3 == esi:
                op1 = 'esi'
            if geto3 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

        if '10000' in getmodplus3:
            reg = 'POP'
            if geto3 == eax:
                op1 = 'eax'
            if geto3 == ecx:
                op1 = 'ecx'
            if geto3 == edx:
                op1 = 'edx'
            if geto3 == esp:
                op1 = 'esp'
            if geto3 == ebp:
                op1 = 'ebp'
            if geto3 == esi:
                op1 = 'esi'
            if geto3 == edi:
                op1 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op1 + '+' + nbyte + ']'
            i += 2
            continue

    if '0x68' in hexx:
        reg = 'PUSH'
        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hex1z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmod = hex1z[:2]
        geto1 = hex1z[-6:-3]
        geto2 = hex1z[-3:]
        getmodplus1 = hex1z[:3]
        getmodplus2 = hex1z[:4]
        getmodplus3 = hex1z[:5]
        checkbytes = hex(ord(fulldata[i + 0]))

        if hex1z == '01101000':
            reg = 'PUSH'
            addbytes1 = hex(ord(fulldata[i + 0]))
            addbytes2 = hex(ord(fulldata[i + 1]))
            addbytes3 = hex(ord(fulldata[i + 2]))
            addbytes4 = hex(ord(fulldata[i + 3]))
            addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                + addbytes1
            addbytes_total1 = re.sub('0x', '', addbytes_total)

            print reg + ' 0x' + addbytes_total1
            i += 4
            continue

    if '0x85' in hexx:
        my_hexdata = hex(ord(fulldata[i - 1]))
        scale = 16
        num_of_bits = 8
        hexcurrent = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

        my_hexdata = hex(ord(fulldata[i + 0]))
        scale = 16
        num_of_bits = 8
        hex1 = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
        getmod = hex1[:2]
        geto2 = hex1[-6:-3]
        geto3 = hex1[-3:]

        checkbytes = hex(ord(fulldata[i + 0]))

        if '11' in getmod:
            reg = 'TEST'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'
            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2 = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            print reg + ' ' + op2 + ', ' + op1
            i += 1
            continue

        if '00' in getmod:
            if '101' in geto3:
                reg = 'TEST'

                if geto2 == eax:
                    op2 = 'eax'
                if geto2 == ecx:
                    op2 = 'ecx'
                if geto2 == edx:
                    op2 = 'edx'
                if geto2 == esp:
                    op2 = 'esp'
                if geto2 == ebp:
                    op2 = 'ebp'
                if geto2 == esi:
                    op2 = 'esi'
                if geto2 == edi:
                    op2 = 'edi'
                addbytes1 = hex(ord(fulldata[i + 1]))
                addbytes2 = hex(ord(fulldata[i + 2]))
                addbytes3 = hex(ord(fulldata[i + 3]))
                addbytes4 = hex(ord(fulldata[i + 4]))
                addbytes_total = addbytes4 + addbytes3 + addbytes2 \
                    + addbytes1
                addbytes_total = re.sub('0x', '', addbytes_total)
                print reg + ' ' + op2 + ', [0x' + addbytes_total \
                    + '], ' + op1
                i += 5
                continue
            else:

                reg = 'TEST'
                if geto2 == eax:
                    op1 = 'eax'
                if geto2 == ecx:
                    op1 = 'ecx'
                if geto2 == edx:
                    op1 = 'edx'
                if geto2 == esp:
                    op1 = 'esp'
                if geto2 == ebp:
                    op1 = 'ebp'
                if geto2 == esi:
                    op1 = 'esi'
                if geto2 == edi:
                    op1 = 'edi'
                if geto3 == eax2:
                    op2 = 'eax'
                if geto3 == ecx2:
                    op2 = 'ecx'
                if geto3 == edx2:
                    op2 = 'edx'
                if geto3 == esp2:
                    op2 = 'esp'
                if geto3 == ebp2:
                    op2 = 'ebp'
                if geto3 == esi2:
                    op2 = 'esi'
                if geto3 == edi2:
                    op2 = 'edi'

                print reg + ' [' + op2 + '], ' + op1
                i += 1
                continue

        if '01' in getmod:
            reg = 'TEST'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue

        if '10' in getmod:
            reg = 'TEST'
            if geto2 == eax:
                op1 = 'eax'
            if geto2 == ecx:
                op1 = 'ecx'
            if geto2 == edx:
                op1 = 'edx'
            if geto2 == esp:
                op1 = 'esp'
            if geto2 == ebp:
                op1 = 'ebp'
            if geto2 == esi:
                op1 = 'esi'
            if geto2 == edi:
                op1 = 'edi'

            if geto3 == eax2:
                op2 = 'eax'
            if geto3 == ecx2:
                op2 = 'ecx'
            if geto3 == edx2:
                op2 = 'edx'
            if geto3 == esp2:
                op2 = 'esp'
            if geto3 == ebp2:
                op2p = 'ebp'
            if geto3 == esi2:
                op2 = 'esi'
            if geto3 == edi2:
                op2 = 'edi'

            nbyte = hex(ord(fulldata[i + 1]))
            print reg + ' [' + op2 + '+' + nbyte + '], ' + op1
            i += 2
            continue
    else:
        print 'Unsupported Opcode: ' + hexx
        continue
