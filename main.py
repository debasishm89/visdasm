import pefile
from pydbg import *
from pydbg.defines import *
import pydasm
import sys
import ConfigParser
import time
import thread

all_jump = ['jmp','je','jne','jg','jge','ja','jae','jl','jz','jle','jnz','jo','jno','js','jns','jb','jnae','jc','jnb','jnc','jbe','jna','jnbe','jnge','jnl','jng','jnle','jp','jpe','jnp','jpo','jcxz','jecxz']
def getregion(dbg,address):
	deref_info = dbg.smart_dereference(address,print_dots=False)
	if "(stack)" in deref_info:
		result = "stack"
	elif "(heap)" in deref_info:
		result = "heap"
	else:
		result = "NA"
	return result
def write_hit_seq(data):
	f = open('final.js','a')
	f.write('\n\n\nhit_seq = '+str(data))
	f.close()
def write_comment(data):
	f = open('final.js','a')
	f.write("\n\n\nlast_address_comnt = {")
	for i in data:
		f.write("'"+hex(i)[:-1]+"':'"+data[i]+"',")
	f.write("'':''}")
	f.close()
def closejs():
	f = open('final.js','a')
	f.write(']')
	f.close()
def addtojsfile(content):
	f = open('final.js','a')
	f.write(str(content))
	f.close()
def startjs():
	f = open('final.js','w')
	f.write('json_obj = [')
	f.close()

def add_to_json_tree(instruction_chunck):
	str = ''
	chunck_id = instruction_chunck[0][0]
	for instruction in instruction_chunck:
		address = instruction[0]
		opcode = instruction[1]
		operand = instruction[2]
		comment = "NA"
		context = "NA"
		str += '\t\t\t\t{ "address": "'+address+'", "opcode": "'+opcode+'","operand":"'+ operand  +'","comment":"'+comment+'","context":"'+ context +'" }'
		str += ',\n'
	temp = '\n\n{ "chunck_id": "' + chunck_id +'",\n"instructions": ['+ str[:-2] +'] },'
	addtojsfile(temp)
def get_ops_details(dbg,ins_str):
	eax = dbg.context.Eax
	ebx = dbg.context.Ebx
	ecx = dbg.context.Ecx
	edx = dbg.context.Edx
	esi = dbg.context.Esi
	edi = dbg.context.Edi
	ebp = dbg.context.Ebp
	esp = dbg.context.Esp
	part = ins_str.split(',',1)
	if len(part) == 1:
		if '[' in part[0]:
			math_expression = part[0].replace('[','').replace(']','')
			try:
				dword = dbg.read_process_memory(eval(math_expression), 4)
				direct = hex(dword) + '('+getregion(dbg,eval(math_expression)) + ')'
			except Exception,e:
				direct = "N/A"
		else:
			try:
				direct = hex(eval(part[0])) + '(' + getregion(dbg,eval(part[0])) + ')'
			except Exception,e:
				direct = "N/A"
		final_comment = part[0] + ':'+ direct
	else:
		if '[' in part[0]:
			math_expression = part[0].replace('[','').replace(']','')
			try:
				dword = dbg.read_process_memory(eval(math_expression), 4)
				direct1 = hex(dword)+ ' ( ' +getregion(dbg,eval(math_expression)) + ')'
			except Exception,e:
				direct1 = "N/A"
		else:
			try:
				direct1 = hex(eval(part[0])) + ' ( ' + getregion(dbg,eval(part[0])) + ')'
			except Exception,e:
				direct1 = "N/A"
##################################################################################
		if '[' in part[1]:
			math_expression = part[1].replace('[','').replace(']','')
			#caluclate eval if possible
			try:
				dword = dbg.read_process_memory(eval(math_expression), 4)
				direct2 = hex(dword)+ ' ( ' +getregion(eval(math_expression)) + ')'
			except Exception,e:
				direct2 = "N/A"
		else:
			try:
				direct2 = hex(eval(part[1]))+ ' ( ' +getregion(eval(part[1])) + ')'
			except Exception,e:
				direct2 = "N/A"
		final_comment = part[0] + ':'+ direct1 + ' & ' + part[1] + ':' + direct2
	return final_comment

def disassemble_range(dbg):
	print '[+] Disassembling the given address range'
	raw_bin = dbg.read_process_memory(start_address, end_address-start_address)
	offset = 0
	chunck = []
	global all_jump_addr	#Holds all Jump address
	all_jump_addr = []		#Including start & end of function
	global bp_to_be_set		#bp for control flow drawing
	bp_to_be_set = []
	global addr_dict		#holding address and corresponding instruction
	addr_dict = {}			#address dictionary
	global addr_cmnt_dict	#holding address and corresponding instruction
	addr_cmnt_dict = {start_address:'NA'}		#address dictionary
	while offset < len(raw_bin):
		i = pydasm.get_instruction(raw_bin[offset:], pydasm.MODE_32)
		instruction = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, start_address)
		instruction = instruction.replace('dword','')
		if offset == 0:
			address = start_address
			next_addr = start_address + i.length
		else:
			address = next_addr
			next_addr = address+i.length
		array = instruction.split(' ',1)
		new = []
		if len(hex(address)) == 9:
			new.append(hex(address)[:-1])
		else:
			new.append(hex(address))
		'''
		addr_dict = {'Address':'Correspoding Instruction String',
			'Address':'Correspoding Array of instruction at that address'
		}
		'''
		addr_dict[address] = instruction
		addr_cmnt_dict[address] = "NA"
		for k in array:new.append(k)
		chunck.append(new)
		#######################################################
		if address == end_address-1:
			bp_to_be_set.append(chunck[0][0])
			add_to_json_tree(chunck)##
		if new[1] in all_jump:
			all_jump_addr.append(address)
			add_to_json_tree(chunck)##
			bp_to_be_set.append(chunck[0][0])
			chunck = []
		######################################################
		offset += i.length
	closejs()
	print '[+] Disassembling Done!'
	return DBG_CONTINUE

##################################################################################
def crash_handler (dbg):
	print '[+] Target Application Crashed'
	write_hit_seq(hit_seq)
	if dbg.debugger_active:
		dbg.terminate_process()
	return DBG_CONTINUE
def printjmp(dbg):
	jmp = dbg.context.Eip
	hit_seq.append( hex(jmp)[:-1] )
	return DBG_CONTINUE
def set_all_jmp_bp(dbg):
	print '[+] Setting Break on all jump instrunctions between ',hex(start_address),'and',hex(end_address)
	disassemble_range(dbg)
	for fun1 in bp_to_be_set:
		addr = int(fun1,16)
		dbg.bp_set(addr,handler=printjmp)
	return DBG_CONTINUE
##################################################################################
def crash_handler1 (dbg):
	print '[+] Target Application Crashed'
	write_comment(addr_cmnt_dict)
	if dbg.debugger_active:
		dbg.terminate_process()
	return DBG_CONTINUE
def printeip(dbg):
	eip = dbg.context.Eip
	cmnt = get_ops_details(dbg,addr_dict[eip].split(' ',1)[1])
	addr_cmnt_dict[eip] = cmnt
	return DBG_CONTINUE
def set_all_addr_bp(dbg):
	print '[+] Setting Break on all instrunctions ',hex(start_address),hex(end_address)
	for fun1 in addr_dict:
		addr = int(fun1)
		dbg.bp_set(addr,handler=printeip)
	return DBG_CONTINUE
##############################################################################################
def parseconfig():
	global exe_file,input_file,time_delay,dll_path,start_address,end_address
	config = ConfigParser.ConfigParser()
	config.read('config.conf')
	exe_file = config.get('Configuration', 'ProgramName', 0) 
	input_file = config.get('Configuration', 'InputFile', 0) 
	time_delay = int(config.get('Configuration', 'Delay_Duration', 0))
	dll_path = config.get('Configuration', 'LoadDll', 0)
	start_address = int(config.get('Configuration', 'Start_Address', 0),16)
	end_address = int(config.get('Configuration', 'End_Address', 0),16)+1
	print '\t[*]Target Application :',exe_file
	print '\t[*]File to be Feed :',input_file
	print '\t[*]The application will run for :',time_delay,'Seconds'
	print '\t[*]Dll File to be load :',dll_path
	print '\t[*]Funtion start point :',hex(start_address)
	print '\t[*]Function End point :',hex(end_address)
	raw_input('[+] If above informations are corrects press enter to continue')

def main():
	print '[+] Reading configuration file'
	parseconfig()
	global hit_seq
	hit_seq = []
	global entry
	pe = pefile.PE(exe_file)
	entry = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
	startjs()	
	print '[+] Starting Application for the first time'
	dbg = pydbg()
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, crash_handler)
	#thread.start_new_thread(stillrunning, (dbg, ))#still running huhh??
	dbg.load(exe_file,input_file)
	dbg.bp_set(entry,handler=set_all_jmp_bp)
	dbg.run()
	print '[+] Running the target application second time to recored dereference information'
	dbg = pydbg()
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, crash_handler1)
	#thread.start_new_thread(stillrunning, (dbg, ))#still running huhh??
	dbg.load(exe_file,input_file)
	dbg.bp_set(entry,handler=set_all_addr_bp)
	dbg.run()
	#####################
if __name__ == '__main__':
	main()
