def run(self):
    try:
        while True:
            if not self.queue.empty():
                line = self.queue.get()
                #print "IN THE PROCESS AT:{} flow: *{}*".format(datetime.now(), line)
                if 'stop' != line:
                    if '10.0.2.15' in line or '31.13.91.6' in line:
                        # Process this flow
                        column_values = self.parsingfunction(line)
                        if column_values[7] == "80" or column_values[6] == "'10.0.2.15'":
                            print(column_values[6], column_values[7])
                            try:
