import re
from collections import defaultdict
import statistics
import sys


gateDict = {"IGATE_CLIENT":"A", "IGATE_VM1B":"B", "IGATE_VM2B":"C", "IGATE_SERVER":"D", "IGATE_VM2A":"E", "IGATE_VM1A":"F"}

ipidDict = defaultdict(dict)


vm1_fwd_array = []
vm2_fwd_array = []
#server_array = []
vm2_rv_array = []
vm1_rv_array = []
serial_fwd_array = []
serial_rv_array = []

overall_array = []

def fun():
	if sys.argv[1] == "serial":
		serial(ipidDict)
	elif sys.argv[1] == "parallel":
		parallel(ipidDict)
	else:
		print "input error"
		sys.exit(0)
	output_date()

def parallel(ipidDict):
	for key in ipidDict:
		#print key
		forward = 1
		if "A" in ipidDict[key] and "B" in ipidDict[key] and "C" in ipidDict[key]:
			a = (long)(ipidDict[key]["A"])
			b = (long)(ipidDict[key]["B"])
			c = (long)(ipidDict[key]["C"])
		elif "D" in ipidDict[key] and "E" in ipidDict[key] and "F" in ipidDict[key]:
			forward = 0
			d = (long)(ipidDict[key]["D"])
			e = (long)(ipidDict[key]["E"])
			f = (long)(ipidDict[key]["F"])
		else:
			forward = -1

		if forward == 1:
			vm1_fwd = b-a
			if vm1_fwd < 0 or vm1_fwd > 1000:
				continue
			vm2_fwd = c-a
			if vm2_fwd < 0 or vm2_fwd > 1000:
				continue
			serial_fwd = max(vm1_fwd,vm2_fwd)
			if serial_fwd < 0 or serial_fwd > 1000:
				continue
			vm1_fwd_array.append(vm1_fwd)
			vm2_fwd_array.append(vm2_fwd)
			serial_fwd_array.append(serial_fwd)
		elif forward == 0:
			vm2_rv = f-d
			if vm2_rv < 0 or vm2_rv > 1000:
				continue
			vm1_rv = e-d
			if vm1_rv < 0 or vm1_rv > 1000:
				continue
			serial_rv = max(vm1_rv, vm2_rv)
			if serial_rv < 0 or serial_rv > 1000:
				continue
			vm2_rv_array.append(vm2_rv)
			vm1_rv_array.append(vm1_rv)
			serial_rv_array.append(serial_rv)
		else:
			continue

def serial(ipidDict):
	for key in ipidDict:
		#print key
		forward = 1
		if "A" in ipidDict[key] and "B" in ipidDict[key] and "C" in ipidDict[key]:
			a = (long)(ipidDict[key]["A"])
			b = (long)(ipidDict[key]["B"])
			c = (long)(ipidDict[key]["C"])
		elif "D" in ipidDict[key] and "E" in ipidDict[key] and "F" in ipidDict[key]:
			forward = 0
			d = (long)(ipidDict[key]["D"])
			e = (long)(ipidDict[key]["E"])
			f = (long)(ipidDict[key]["F"])
		else:
			forward = -1

		if forward == 1:

			vm1_fwd = b-a
			if vm1_fwd < 0 or vm1_fwd > 1000:
				continue
			vm2_fwd = c-b
			if vm2_fwd < 0 or vm2_fwd > 1000:
				continue
			serial_fwd = c-a
			if serial_fwd < 0 or serial_fwd > 1000:
				continue
			vm1_fwd_array.append(vm1_fwd)
			vm2_fwd_array.append(vm2_fwd)
			serial_fwd_array.append(serial_fwd)
		elif forward == 0:
			vm2_rv = e-d
			if vm2_rv < 0 or vm2_rv > 1000:
				continue
			vm1_rv = f-e
			if vm1_rv < 0 or vm1_rv > 1000:
				continue
			serial_rv = f-d
			if serial_rv < 0 or serial_rv > 1000:
				continue
			#server_array.append(server_fw)
			vm2_rv_array.append(vm2_rv)
			vm1_rv_array.append(vm1_rv)
			serial_rv_array.append(serial_rv)
		else:
			continue

def output():
	#print "vm1_fwd_array"
	#for item in vm1_fwd_array:
		#print item
	#print "vm2_fwd_array"
	#for item in vm2_fwd_array:
		#print item

	#print "vm2_rv_array"
	#for item in vm2_rv_array:
		#print item
	#print "vm1_rv_array"
	#for item in vm1_rv_array:
		#print item

	#print "serial_fwd_array"
	#for item in serial_fwd_array:
		#print item
	#print "serial_rv_array"
	#for item in serial_rv_array:
		#print item


	if len(serial_fwd_array) != 0:
		print "fwd mean: "+ str(statistics.mean(serial_fwd_array))
		print "fwd median: " + str(statistics.median(serial_fwd_array))
		print "fwd stdev: " + str(statistics.stdev(serial_fwd_array))
	
	if len(serial_rv_array) != 0:
		print "rv mean: "+ str(statistics.mean(serial_rv_array))
		print "rv median: " + str(statistics.median(serial_rv_array))
		print "rv stdev: " + str(statistics.stdev(serial_rv_array))
	
	print "^^^^^^^"
	if len(vm1_fwd_array) != 0:
		print "vm1_fwd mean: "+ str(statistics.mean(vm1_fwd_array))
		print "vm1_fwd median: " + str(statistics.median(vm1_fwd_array))
		print "vm1_fwd stdev: " + str(statistics.stdev(vm1_fwd_array))
	if len(vm2_fwd_array) != 0:
		print "vm2_fwd mean: "+ str(statistics.mean(vm2_fwd_array))
		print "vm2_fwd median: " + str(statistics.median(vm2_fwd_array))
		print "vm2_fwd stdev: " + str(statistics.stdev(vm2_fwd_array))
	if len(vm1_rv_array) != 0:
		print "vm1_rv mean: "+ str(statistics.mean(vm1_rv_array))
		print "vm1_rv median: " + str(statistics.median(vm1_rv_array))
		print "vm1_rv stdev: " + str(statistics.stdev(vm1_rv_array))
	if len(vm2_rv_array) != 0:
		print "vm2_rv mean: "+ str(statistics.mean(vm2_rv_array))
		print "vm2_rv median: " + str(statistics.median(vm2_rv_array))
		print "vm2_rv stdev: " + str(statistics.stdev(vm2_rv_array))


def output_date():
	if len(serial_fwd_array) != 0:
		for item in serial_fwd_array:
			print item
	print statistics.mean(serial_fwd_array)
	print statistics.median(serial_fwd_array)


fileName = sys.argv[2]
string = "IGATE_CLIENT ipid 2222, 793274038470 microseconds since epoch"

fileReader = open(fileName, "r")
for item in fileReader:
	item = item.strip()
	regex = r"(IGATE_[a-zA-Z]+|IGATE_[a-zA-Z]+\d[a-zA-Z]+) ipid (\d+), (\d+)"
	
	#item = string

	if 	re.search(regex, item):
		match = re.search(regex, item)
		#print "Match at index %s, %s" % (match.start(), match.end())
		#print "Full match: %s" % (match.group(0))
		#print "Gate: %s" % (match.group(1))
		gate = match.group(1)
		#print "ipid: %s" % (match.group(2))
		ipid = match.group(2)
		#print "time: %s" % (match.group(3))
		time = match.group(3)
		#pidList[
		ipidDict[ipid][gateDict[gate]] = time
	else:
		#print "The regex pattern does not match. :("
		if item == "desc: \'test_namespace_eth22/VPort\'":
			#print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
			vm1_fwd_array = []
			vm2_fwd_array = []
			#server_array = []
			vm2_rv_array = []
			vm1_rv_array = []
			serial_fwd_array = []
			serial_rv_array = []
			fun()
		pass
fun()
