#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on Apr 16, 2013 v0.1
Modified and added scanning function, Dec 14, 2013 v0.2
Added fuzzing feature for specific function code, Apr 30, 2014 v0.5

@author: Ali, TJ
'''
import socket
import sys		#提供了许多函数和变量来处理 Python 运行时环境的不同部分
from types import *		#判断数据类型
import struct		#完成字符串的转换，特别是要在网络上进行数据传输的话。
import time
import logging

HOST = '127.0.0.1'    # The remote host
dest_port = 502       # The same port as used by the server
TANGO_DOWN = ''
sock = None
dumbflagset = 0

def create_connection(dest_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error, msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)

    HOST = dest_ip
    try:
        sock.settimeout(0.5)
        sock.connect((HOST, dest_port))
    except socket.error, msg:
        logging.exception("Connection Failed!")
    else:
        logging.info("Connected to Server: %s" % dest_ip)

    return sock


def hexstr(s):
    return '-'.join('%02x' % ord(c) for c in s)
	#join是字符串操作函数，操作的也是字符串，其作用结合字符串使用，常常用于字符连接操作
	#ord 是以一个字符为参数返回其对于的ASCII值。
    #%02x 表示以十六进制形式输出 02 表示不足两位,前面补0输出;出过两位,不影响 print "%04x" %246
    #00f6


def dumb_fuzzing(dest_ip):#盲测
	sock = create_connection(dest_ip, dest_port)
	"""	
	tcp/ip上的modbus协议进行分析总长度为256字节
	modbus tcp协议数据帧格式  | MBAP报文头（7）| 功能代码（1） | 数据（248字节可用） |
	MBAP报文头格式 |传输标志（2） | 协议标志（2）|  长度（2）|单元标志（1）|
	具体内容查看相关文档	
	"""	
	transID = 0		#传输（事务处理）标志：标志某个modbus询问/应答的传输	
	protoID = 0		#协议标志：0=modbus协议	
	unitID = 0		#单元标志：为了系统内路由，使用这个域，用big-endian（大端>）编码不同域。
	lengthOfFunctionData = 1	#长度：后续字节数量
	prevField = ""
	for functionCode in range(0,255):#多层循环嵌套什么意思？因为是盲测所以一直循环么？
		for functionData6 in range(0, 255):
		    for functionData5 in range(0, 255):
				for functionData4 in range(0, 255):
				    for functionData3 in range(0, 255):
						for functionData2 in range(0, 255):
						    for functionData1 in range(0, 255):
								functionDataField = prevField + struct.pack(">B", functionData1)
								#>表示大端，B表示一个字节（Byte，最大255），struct用于将数据打包为十六进制数据流，
                                # 在网络上传输。
								#print"%s" % hexstr(functionDataField)
								length = 2 + lengthOfFunctionData
								ModbusPacket = struct.pack(">H", transID) + \
									struct.pack(">H", protoID) + \
									struct.pack(">H", length) + \
									struct.pack(">B", unitID) + \
									struct.pack(">B", functionCode) + \
									functionDataField
								#H表示两个字节（最大65535），B表示一个字节
								logging.debug("%s" % hexstr(ModbusPacket))#将发送的数据写到logging中
								#print"%s" % hexstr(ModbusPacket)
								#将数据层层封装起来，构成完整的modbus数据包
								
								try:
								    sock.send(ModbusPacket)
								except socket.timeout:
								    logging.exception("Sending Timed Out!")
								except socket.error:
								    logging.exception("Sending Failed!")
								    sock.close()
								    sock = create_connection(dest_ip, dest_port)
								    logging.info("Try to Reconnect...")
								else: 
								    logging.debug("Sent Packet: %s" % hexstr(ModbusPacket))
								    print "Sent: %s" % hexstr(ModbusPacket)
				'''                 try:
										data = sock.recv(1024)
										print 'Received %s:' % repr(data)
									except socket.timeout:
										print ''
									except socket.error:
										sock.close()
										sock = create_connection(dest_ip, dest_port)

									sock.close()
				'''
def smart_fuzzing_with_user_input(dest_ip, msg):#根据用户输入来进行smart_fuzzing
	#根据调用关系来看，传入的msg参数的数据类型是str。
    sock = create_connection(dest_ip, dest_port)
    strInput = msg		
    dataSend = ""
    cnt = 1
    for chInput in strInput:  
	#根据simulator函数传入的msg来看，strInput中包含了MBAP头和功能码00，一共8个字节长，字符串中是一串16进制数。
        if cnt%2 == 0:		#因为一个字符打包后会生成一个字节数，所以这里只去字符串中的地位打包，以保证打包的长度跟原来的包头一致
           intInput = int(chInput,16)	
		   #参数16是表示被转换的内容当前为16进制数，默认值为10进制
		   #例：int（'225',16）为549
           dataSend += struct.pack(">B", intInput)#按照发送要求打包成16进制
        cnt += 1
    try:
		sock.send(dataSend)
		print 'sent: %s' % hexstr(dataSend)
    except socket.error:
		sock.close()
		print 'trying to create connection again'
		sock = create_connection(dest_ip, dest_port)
    try:
        dataRecv = sock.recv(1024)
        print >>sys.stderr, 'received: %s' % hexstr(dataRecv)
    except socket.timeout:
        print 'recv timed out!'
    except socket.error:
        sock.close()
        sock = create_connection(dest_ip, dest_port)
    sock.close()

def simulator(dest_ip): #仿真器
    value1 = 0
    value2 = 100
    transID = 0#记录发出的是哪个信息，作为请求响应的标志。在循环时会做+1处理。
    while True:
        strTransID = "%0.4x" % transID	#格式化字符输出，16进制显示，占一个字节
        strHex1 = "%0.4x" % value1
        msg1 = strTransID + "0000000B01060000" + strHex1
        ##"0000000B01060000"是十六进制数，MBAP头和功能码00，一共8个字节
        #传输标识符是变化的，每次加1 ，协议标志是0000；长度是000B，即11字节。为什么是11个字节？
        # 单元码是01，功能码是06 :把二进制写入寄存器
        #功能码后是寄存器地址，2个字节，，寄存器1是0000，从。strHex1是待写入的值，两个字节。
        smart_fuzzing_with_user_input(dest_ip, msg1)
        transID += 1
        strTransID = "%0.4x" % transID
        strHex2 = "%0.4x" % value2
        msg2 = strTransID + "0000000B01060001" + strHex2#寄存器2 地址0001

        smart_fuzzing_with_user_input(dest_ip, msg2)

        value1 += 1
        value2 -= 1
        transID += 1
        if (value1 > 100):
			value1 = 0
        if (value2 < 0):
			value2 = 100
        time.sleep(0.3)


def smart_fuzzing_for_func08h(dest_ip):	
    sock = create_connection(dest_ip, dest_port)
    transID = 0
    protocolID = 0
    length = 6
    unitID = 0
    funcCode = 8 # Diagnostic，回送诊断，把诊断校验报文送从机，对通信处理进行评价
    subFunction = 13 # sub function code start from 0x0000
    dataField = 0

    while True:
        packet = struct.pack(">H", transID) + struct.pack(">H", protocolID) + struct.pack(">H", length) + \
                 struct.pack(">B", unitID) + struct.pack(">B", funcCode) + struct.pack(">H", subFunction) + \
                 struct.pack(">H", dataField)
        try:
			sock.send(packet)
        except socket.error:
			sock.close()
			sock = create_connection(dest_ip, dest_port)
        try:
			dataRecv = sock.recv(1024)
        except socket.timeout:
			sys.stdout.write('1.time out\n')
        except socket.error:
			sock.close()
			sock = create_connection(dest_ip, dest_port)

        if len(dataRecv) > 0:
			print "Sent: %s" % hexstr(packet)
			print "Recv: %s" % hexstr(dataRecv)

#      if len(dataRecv) < 1:
#        sock.close()
#        sock = create_connection(dest_ip, dest_port)
#        try:
#          sock.send(packet)
#          print "Sent2: %s" % hexstr(packet)
#        except socket.error:
#          print 'FAILED TO SEND2'
#        try:
#          dataRecv = sock.recv(1024)
#          print "Recv2 : %s" % hexstr(dataRecv)
#        except socket.timeout:
#          sys.stdout.write('2.time out\n')
#        except socket.error:
#          print 'FAILED TO RECV2'

        transID = transID + 1
#      subFunction = subFunction + 1
        dataField = dataField + 1

def smart_fuzzing_for_func0Fh(dest_ip):
    sock = create_connection(dest_ip, dest_port)
    transID = 0
    protocolID = 0
    length = 8  #功能码1B，起始地址2B，输出数量2B：0x0000-0x07B0，字节数1B，N*；
                #输出值N*×1 个字节，*N＝输出数量/8，如果余数不等于 0，那么N = N+1，
    unitID = 0
    funcCode = 15 # Write Multiple coils，写多线圈，强制一串连续逻辑线圈的通断。
    startAddr = 0 # start from 0x0000，两个字节
#    startAddr = 122 # start from 0xFFFF
    quantityOutputs = 8 #输出数量为什么定为8？
    if (quantityOutputs % 8 == 0):
        byteCount = quantityOutputs / 8
    else:
        byteCount = quantityOutputs / 8 + 1
    value = 255

    loopCounter = 0 #循环计数
    while True:
        packet = struct.pack(">H", transID) + struct.pack(">H", protocolID) + struct.pack(">H", length) + \
                 struct.pack(">B", unitID) + struct.pack(">B", funcCode) + struct.pack(">H", startAddr) + \
                 struct.pack(">H", quantityOutputs) + struct.pack(">B", byteCount) + struct.pack(">B", value) + \
                 struct.pack(">B", 255)*loopCounter
        try:
			sock.send(packet)
#            print "Sent: %s" % hexstr(packet)
        except socket.error:
			sock.close()
			sock = create_connection(dest_ip, dest_port)
        try:
			dataRecv = sock.recv(1024)
			print "Recv : %s" % hexstr(dataRecv)
        except socket.timeout:
			sys.stdout.write('1.time out\n')
        except socket.error:
			sock.close()
			sock = create_connection(dest_ip, dest_port)

        if len(dataRecv) < 1:
			sock.close()
			sock = create_connection(dest_ip, dest_port)
			try:
			    sock.send(packet)
			    print "Sent2: %s" % hexstr(packet)
			except socket.error:
			    print 'FAILED TO SEND2'
			try:
			    dataRecv = sock.recv(1024)
			    print "Recv2 : %s" % hexstr(dataRecv)
			except socket.timeout:
			    sys.stdout.write('2.time out\n')
			except socket.error:
			    print 'FAILED TO RECV2'

        transID = transID + 1
        loopCounter = loopCounter + 1

def smart_fuzzing_for_func10h(dest_ip):
    sock = create_connection(dest_ip, dest_port)
    transID = 0
    protocolID = 0
    length = 9
    unitID = 0
    funcCode = 16 # Write Multiple registers,预置多寄存器,把具体的二进制值装入一串连续的保持寄存器
#    startAddr = 0 # start from 0x0000
    startAddr = 122 # start from 0xFFFF
    quantityReg = 1
    byteCount = 2*quantityReg
    value = 65535

    loopCounter = 0
    while True:
        packet = struct.pack(">H", transID) + struct.pack(">H", protocolID) + struct.pack(">H", length) + \
               struct.pack(">B", unitID) + struct.pack(">B", funcCode) + struct.pack(">H", startAddr) + \
               struct.pack(">H", quantityReg) + struct.pack(">B", byteCount) + struct.pack(">H", value) + \
               struct.pack(">B", 255)*loopCounter
        try:
            sock.send(packet)
            print "Sent: %s" % hexstr(packet)
        except socket.error:
			sock.close()
			sock = create_connection(dest_ip, dest_port)
        try:
			dataRecv = sock.recv(1024)
			print "Recv : %s" % hexstr(dataRecv)
        except socket.timeout:
			sys.stdout.write('1.time out\n')
        except socket.error:
			sock.close()
			sock = create_connection(dest_ip, dest_port)

        if len(dataRecv) < 1:
			sock.close()
			sock = create_connection(dest_ip, dest_port)
			try:
			    sock.send(packet)
			    print "Sent2: %s" % hexstr(packet)
			except socket.error:
			    print 'FAILED TO SEND2'
			try:
			    dataRecv = sock.recv(1024)
			    print "Recv2 : %s" % hexstr(dataRecv)
			except socket.timeout:
			    sys.stdout.write('2.time out\n')
			except socket.error:
			    print 'FAILED TO RECV2'
        transID = transID + 1
        loopCounter = loopCounter + 1
#    sock.close()

 

def atod(a): # ascii_to_decimal，从IP地址字符串转换为整数值
    return struct.unpack("!L",socket.inet_aton(a))[0]

def dtoa(d): # decimal_to_ascii，从网络字节序的数字转换为IP地址（点号分隔）
    return socket.inet_ntoa(struct.pack("!L", d))


def scan_device(ip_range):
    net,_,mask = ip_range.partition('/')
    mask = int(mask)	#子网掩码最多32bit（4*8bit）
    net = atod(net)     #把ip地址转换成十进制
    '''
    	ip='10.128.32.147/4'
    	net,_,mask = ip.partition('/')
    	net='10.128.32.147'
    	_ = '/'
    	mask = '4'
    '''
    for dest_ip in (dtoa(net+n) for n in range(0, 1<<32-mask)):
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        except socket.error, msg:
            sock.close()

        try:
            sock.settimeout(0.2)
            sock.connect((dest_ip, dest_port))
        except socket.error, msg:
            print "connection error at %s" % dest_ip
            continue
        except socket.timeout:
            print 'ip %s timeout error' % dest_ip
            continue

        unitID = 0
        dataRecv = ''
        while True:
            dataSend =  struct.pack(">H", 0) \
                            + struct.pack(">H", 0) \
                            + struct.pack(">H", 6) \
                            + struct.pack(">B", unitID) \
                            + struct.pack(">B", 3) \
                            + struct.pack(">H", 0) \
                            + struct.pack(">H", 1)
            try:
                sock.send(dataSend)
                print "Sent: %s to %s" % (repr(dataSend), dest_ip)
            except socket.error:
                print 'FAILED TO SEND'
                #sock.close()
                #continue

            try:
                dataRecv = sock.recv(1024)
                print "Recv : %s" % repr(dataRecv)
            except socket.timeout:
                sys.stdout.write('Fail:timeout!')

            if len(dataRecv) < 1:
                sys.stdout.write('Fail:')
                unitID += 1
            else:
                print '\n unit ID %d found at IP %s' % (unitID, dest_ip)
                if dumbflagset == 1 :
                    print 'now starting dumb fuzzing'
                    dumb_fuzzing(dest_ip)
                break
    sock.close()


# main starts here

if len(sys.argv) < 3:	#用来获取命令行参数
    print "modbus fuzzer v0.5"
    print ""
    print "Usage: python modFuzzer.py [-D] [destination_IP]"
    print "                           [-I] [destination_IP] [packet]"
    print "                           [-S] [IP_range]"
    print "                           [-SD] [IP_range]"
    print "                           [-S08] [destination_IP]"
    print "                           [-S0F] [destination_IP]"
    print "                           [-S10] [destination_IP]"
    print "                           [-SIM] [destination_IP]"
    print " "
    print "Commands:"
    print "Either long or short options are allowed."
    print "  --dumb    -D   Fuzzing in dumb way"
    print "  --input   -I   Fuzzing with given modbus packet"
    print "  --scan    -S   Scan the modbus device(s) in given IP range"
    print "  --sc_dumb -SD  Scan the device(s) and doing dumb fuzzing"
    print "  --f08     -F08 Fuzzing using function code 0x08"
    print "  --f0f     -F0F Fuzzing using function code 0x0F"
    print "  --f10     -F10 Fuzzing using function code 0x10"
    print "  --sim     -SIM Working in simulator mode"
#    print " "
#    print "Option:"
#    print "  --port    -p  Port number"
    print " "
    print "Example:"
    print "python modFuzzer.py -D 192.168.0.123"
#    print "python modFuzzer.py -D 192.168.0.123 -p 8888"
    print "python modFuzzer.py -I 192.168.0.23 0000000000060103000A0001"
    print "python modFuzzer.py -S 192.168.0.0/24"
    print "python modFuzzer.py -F10 192.168.0.0"
    print ""
    exit(1)

argv1 = sys.argv[1]		#获取命令行第二个参数，如：--D
argv2 = sys.argv[2]		#获取命令行第三个参数，如：192.168.0.123
argv3 = ''
if len(sys.argv) > 3:
    argv3 = sys.argv[3]

if (argv1=='-D') or (argv1=='--dumb'):	# dumb fuzzing
    dumb_fuzzing(argv2)
    sys.exit(1)

elif (argv1=='-I') or (argv1=='--input'):	# smart user input
    smart_fuzzing_with_user_input(argv2, argv3)

elif (argv1=='-S') or (argv1=='--scan') or (argv1=='-SD'):       # scan device
    if argv1 =='-SD' :
        dumbflagset = 1 
    scan_device(argv2)

elif (argv1=='-F08') or (argv1=='--f08'): # smart fuzzing for function code 0x08
    smart_fuzzing_for_func08h(argv2)

elif (argv1=='-S0F') or (argv1=='--f0f'): # smart fuzzing for function code 0x0F
    smart_fuzzing_for_func0Fh(argv2)

elif (argv1=='-S10') or (argv1=='--f10'): # smart fuzzing for function code 0x10
    smart_fuzzing_for_func10h(argv2)

elif (argv1=='--sim') or (argv1=='--sim'):
    simulator(argv2)

sys.exit(0)
