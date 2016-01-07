import sys
def buildstr():
    if len(sys.argv) == 2:
        s = sys.argv[1]
        output = 'unsigned char str%s[] = { \n' % (s)
        buf = '\t'
        for c in s:
            buf += "'%c' ^ XOR_KEY, " % (c)
            if len(buf) > 60:
                output += buf + "\n"
                buf = '\t'

        if buf == '\t': buf = ''
        output += buf + 'XOR_KEY\n};'
        print output

def buildstr2():
    if len(sys.argv) == 2:
        s = sys.argv[1]
        print 'char str%s[%d];\n' %( s, len(s) + 1)
        output = '{ '
        for c in s:
            if c == '\\':
                c = '\\\\'
            output += "'%s', " %(str(c))
        output += "'\\0'},\n"
        print output

        output = '{ '
        for c in s:
            if c == '\\':
                c = '\\\\'
            output += "L'%s', " %(str(c))
        output += "L'\\0'},\n"
        print output

        output = '{ '
        for c in s:
            if c == '\\':
                c = '\\\\'
            output += "'%s' ^ XOR_KEY, " %(str(c))
        output += "XOR_KEY},\n"
        print output

def main():
    buildstr2()

if __name__ == '__main__':
    main()
