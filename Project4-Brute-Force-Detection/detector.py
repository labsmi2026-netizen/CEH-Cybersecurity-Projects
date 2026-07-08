        try:
            p = subprocess.Popen(['tail', '-f', '-n', '0', self.log_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in p.stdout:
                self.process_line(line)
        except KeyboardInterrupt:
            pass
