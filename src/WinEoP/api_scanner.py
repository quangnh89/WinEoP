#-------------------------------------------------------------------------------
# Name:        api_scanner.py
# Purpose:     auto generate code for WinEoP
# Author:      quangnh89
# Created:     2015
#-------------------------------------------------------------------------------

import re
file_name = r'Utils\ApiStub.h'

# convert a string to encoded-buffer
def buildstrElement(s, encoded = True):
    a = 'unsigned char str%s[%d];' % ((s.replace('.', '_')), len(s) + 1)
    b = '{ '
    for c in s:
        if encoded:
            b += "'%c' ^ XOR_KEY, " % (c)
        else:
            b += "'%c', " % (c)

    if encoded:
        b += 'XOR_KEY},'
    else:
        b += "'\0'},"

    return (a, b)

# write code between '// -- [Auto generated] END --' and '// -- [Auto generated] BEGIN --' tag
def WriteCodeToFile(src_file, data):
    start = False
    end = False
    write_pos = 0
    remain_line = []
    src_f = open(src_file, 'r+t')
    while True:
        line = src_f.readline()
        if line == '':
            break

        # start write from here
        if not start and line.find('// -- [Auto generated] BEGIN --') != -1:
            start = True
            if write_pos == 0: write_pos = src_f.tell()
            continue
        # end
        if not end and line.find('// -- [Auto generated] END --') != -1:
            end = True

        if not start:
            continue
        if end:
            remain_line.append(line)

    if write_pos > 0:
        src_f.truncate(write_pos)
        src_f.seek(0, 2)
        for i in data:
            src_f.writelines(i + '\n')
        for i in remain_line:
            src_f.writelines(i)
    src_f.close()

# some types should be modified due to conflict
custom_function_type= {'SOCKET': 'FP_SOCKET'}

def main():
    f = open(file_name, 'rt')
    begin = False
    leave = False
    la = []
    lb = []
    lc = []
    while True:
        line = f.readline() # read each line
        if line == '':
            break
        if line.find('{') != -1:
            begin = True
            continue
        if line.find('}') != -1:
            break
        if line.find('//') != -1 and line.find('#') != -1: # comment
            continue
        if line.find('**leave**') != -1: # **leave**
            leave = True
            continue
        if not begin:
            continue
        if leave:
            continue
        if line.find('#if') != -1 or line.find('#elif') != -1 or line.find('#endif') != -1 or line.find('#else') != -1: # #if, #else, #elif, #endif
            if line[len(line) -1] == '\n':
                line = line[:-1]
            lc.append(line)
            continue

        # search for library.dll
        if line.find('//') != -1:
            searchObj = re.search('[A-Za-z0-9_]*(\.[A-Za-z0-9]{3})?\n', line, re.M|re.I)
            if (searchObj):
                dll_name = searchObj.group(0)
                dll_name = dll_name[:-1]
                if dll_name == 'kernel32.dll':
                    continue
                a, b = buildstrElement(dll_name)
                c = 'LOAD_ENCODED_LIB(%s);' % dll_name.replace('.', '_')
                la.append(a)
                lb.append(b)
                lc.append(c)
                continue

        # processing function name
        searchObj = re.search('\S*;', line, re.M|re.I)
        if searchObj:
            found_name = searchObj.group(0)
            matchObj = re.search('[A-Za-z0-9]*', found_name, re.M|re.I)
            if matchObj:
                function_name =matchObj.group(0)
                a, b = buildstrElement(function_name)
                function_type = function_name.upper()
                if function_type in custom_function_type:
                    function_type = custom_function_type[function_type]
                c = 'GET_ENCODED_FUNCTION(hModule, %s, %s);' % (function_name, function_type)
                la.append(a)
                lb.append(b)
                lc.append(c)

    f.close() # close apistub.h

    WriteCodeToFile('StringTable.h', la)
    WriteCodeToFile('StringTable.cpp', lb)
    WriteCodeToFile(r'Utils\ApiStub.cpp', lc)
if __name__ == '__main__':
    main()
