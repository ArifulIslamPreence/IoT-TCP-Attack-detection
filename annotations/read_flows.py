with open('/home/faizan/dalhousie/181021.csv', 'r') as f: # open in readonly mode
	for line in f.readlines()[1:]:
	  values = line.strip().split(',')

	  # try:
	  #   start_value = int(values[0])
	  #   end_value = int(values[1])
	  # except:
	  #   continue
	  time = ''.join(e for e in values[0] if e.isalnum())

	  print(time)