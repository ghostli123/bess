import re
from collections import defaultdict
import statistics
import sys



fileName = sys.argv[1]
string = "IGATE_CLIENT ipid 2222, 793274038470 microseconds since epoch"

fileIndex = 0
writeToFile = open("mediate/"+str(fileIndex), 'w')
fileReader = open(fileName, "r")
for item in fileReader:
	item = item.strip()
	if item.startswith("cmd: \'list_modules\'"):
		writeToFile.close()
		fileIndex += 1
		writeToFile = open("mediate/"+str(fileIndex), 'w')
	
	writeToFile.write(item+"\n")

