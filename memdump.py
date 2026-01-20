import frida
import sys
import os
import argparse
import logging
import time
import re
import glob
import shutil
import concurrent.futures

# --- CONFIGURATION ---
CHUNK_SIZE_MB = 1
MIN_STRING_LENGTH = 4
MAX_WORKERS = os.cpu_count()

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

class LoggerSetup:
    @staticmethod
    def setup(log_file=None):
        logger = logging.getLogger("MemTool")
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # Console Handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(ch)

        # File Handler
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            logger.info(f"{GREEN}[+] Logging debug data to: {log_file}{RESET}")

        return logger

logger = None 

class MemoryDumper:
    def __init__(self, target_app, dump_dir):
        self.target_app = target_app
        self.dump_dir = dump_dir
        self.session = None
        self.script = None

        if not os.path.exists(self.dump_dir):
            os.makedirs(self.dump_dir)

    def on_message(self, message, data):
        """
        Handles messages sent from JavaScript.
        Distinguishes between LOGS (text) and CHUNKS (binary file data).
        """
        if message['type'] == 'send':
            payload = message['payload']
            
            # --- FIX: Check if it's a Log Message first ---
            if 'type' in payload and payload['type'] == 'log':
                logger.info(f"{CYAN}[Device Log] {payload['msg']}{RESET}")
                return
            
            # --- Handle Data Chunks ---
            if 'name' in payload:
                filename = f"{payload['name']}.bin"
                filepath = os.path.join(self.dump_dir, filename)

                try:
                    with open(filepath, "ab") as f:
                        f.write(data)
                except Exception as e:
                    logger.error(f"Failed to write chunk for {filename}: {e}")
            else:
                logger.debug(f"Received unknown payload: {payload}")
                
        elif message['type'] == 'error':
            logger.error(f"Frida Script Error: {message['stack']}")

    def start(self):
        try:
            device = frida.get_usb_device()
            logger.info(f"{YELLOW}[*] Connecting to application '{self.target_app}'...{RESET}")
            
            self.session = device.attach(self.target_app)
            logger.info(f"{GREEN}[+] Attached successfully.{RESET}")

            js_code = """
            rpc.exports = {
                dumpRanges: function() {
                    var ranges = Process.enumerateRanges('rw-');
                    var rangeCount = ranges.length;
                    
                    // Send a LOG message (handled by Python now)
                    send({type: 'log', msg: 'Found ' + rangeCount + ' memory ranges.'});
                    
                    var CHUNK_SIZE = 1024 * 1024; // 1MB

                    ranges.forEach(function(range) {
                        try {
                            var base = range.base;
                            var size = range.size;
                            var offset = 0;
                            var rangeName = "mem_" + base;

                            while (offset < size) {
                                var bytesToRead = Math.min(CHUNK_SIZE, size - offset);
                                var chunk = base.add(offset).readByteArray(bytesToRead);
                                
                                // Send DATA message
                                send({
                                    name: rangeName,
                                    size: bytesToRead,
                                    is_chunk: true
                                }, chunk);

                                offset += bytesToRead;
                                Thread.sleep(0.01); 
                            }
                        } catch (e) { }
                    });
                    return rangeCount;
                }
            };
            """

            self.script = self.session.create_script(js_code)
            self.script.on('message', self.on_message)
            self.script.load()

            logger.info(f"{YELLOW}[*] Starting memory dump (Chunked Mode)...{RESET}")
            count = self.script.exports_sync.dump_ranges()
            
            logger.info(f"{GREEN}[✓] Dump Complete. Processed {count} regions.{RESET}")
            
        except Exception as e:
            logger.critical(f"{RED}[!] Error: {e}{RESET}")
            sys.exit(1)
        finally:
            if self.session:
                self.session.detach()

class StringExtractor:
    @staticmethod
    def extract_from_file(filepath):
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            
            chars = r"[\x20-\x7E]{" + str(MIN_STRING_LENGTH) + r",}"
            extracted = []
            
            for match in re.finditer(chars.encode('utf-8'), content):
                extracted.append(match.group().decode('utf-8'))
            
            if not extracted:
                return None

            header = f"\n--- SOURCE: {os.path.basename(filepath)} ---\n"
            return header + "\n".join(extracted) + "\n"
        except Exception:
            return None

    def process(self, input_dir, output_file):
        logger.info(f"{YELLOW}[*] Starting String Extraction...{RESET}")
        
        files = glob.glob(os.path.join(input_dir, "*.bin"))
        total_files = len(files)
        
        if total_files == 0:
            logger.warning("No binary files found.")
            return

        logger.info(f"{GREEN}[+] Processing {total_files} files using {MAX_WORKERS} cores.{RESET}")
        
        with open(output_file, "w", encoding="utf-8") as outfile:
            with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(self.extract_from_file, f): f for f in files}
                
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        outfile.write(result)
                    
                    completed += 1
                    if completed % 50 == 0 or completed == total_files:
                        percent = (completed / total_files) * 100
                        sys.stdout.write(f"\r{CYAN}Progress: {percent:.1f}% ({completed}/{total_files}){RESET}")
                        sys.stdout.flush()

        print()
        logger.info(f"{GREEN}[✓] Output Saved: {output_file}{RESET}")

def main():
    global logger
    
    parser = argparse.ArgumentParser(description="Professional Android Memory Forensics Tool")
    parser.add_argument("-p", "--package", required=True, help="Target Application Name")
    parser.add_argument("-o", "--output", required=True, help="Final text output file")
    parser.add_argument("--log", help="Path to save debug logs")
    parser.add_argument("--keep-bin", action="store_true", help="Keep raw .bin files")
    
    args = parser.parse_args()
    logger = LoggerSetup.setup(args.log)
    temp_dump_dir = f"{args.package.replace(' ', '_')}_dump_temp"
    
    try:
        dumper = MemoryDumper(args.package, temp_dump_dir)
        dumper.start()
        
        extractor = StringExtractor()
        extractor.process(temp_dump_dir, args.output)
        
        if not args.keep_bin:
            logger.info(f"{YELLOW}[*] Cleaning up temp files...{RESET}")
            shutil.rmtree(temp_dump_dir)
            logger.info(f"{GREEN}[✓] Cleanup complete.{RESET}")
        else:
            logger.info(f"{YELLOW}[*] Raw binaries kept in: {temp_dump_dir}{RESET}")

    except KeyboardInterrupt:
        logger.warning(f"\n{RED}[!] Interrupted by user.{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    print("""

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣶⣶⣶⣶⣶⠖⢀⣀⣤⣤⣄⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣭⣭⣭⣭⢹⣿⣷⡀
⠀⠀⠀⠀⢀⣴⣾⠿⠟⢋⣩⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⣿⣿⣿⢸⣿⣿⣷
⠀⠀⠀⠀⠉⠉⣀⣴⣾⣿⣿⣿⣿⣿⣿⡿⠛⠛⠛⣿⣿⡇⣿⣿⣿⣿⣸⣿⣿⣿
⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⡿⠋⣠⣄⢠⣄⠘⣿⣿⣮⣽⣯⣵⣿⣿⣿⠻
⠀⠀⣴⣿⣿⣿⣿⣿⣿⡿⠟⠋⣁⣴⣿⣿⣿⣿⣿⡆⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀
⠀⣼⣿⣿⣿⣿⠟⢋⣁⣀⣤⣾⣿⣿⣿⣿⣿⣯⣭⣭⣬⣭⣭⣭⣭⡭⠵⠶⠶⠀
⢰⣿⣿⠋⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣶⣶⣶⣶⣾⣿⣿⣿⠀
⣿⣿⠃⢀⣴⣿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⢻⣿⣿⡇
⠻⠏⠀⢸⣿⣿⡄⠀⠈⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⢸⣿⣿⡇
⠀⠀⠀⢸⣿⣿⣷⣄⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⢀⣴⣿⣿⣿⠇
⠀⠀⠀⠸⣿⣿⣿⣿⣿⣶⣤⣀⣀⣿⣿⣿⣿⣿⣿⣃⣀⣤⣴⣾⣿⣿⣿⣿⡿⠀
⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⢻⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣽⢻⣿⣿⣿⣿⣿⣯⣤⣀⣬⣿⣿⣿⣿⣿⣿⢫⣾⡆⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢼⣿⡏⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣿⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⣿⣾⢻⡿⣿⣿⢿⡿⣿⣿⢿⡿⡿⣿⢱⣿⣿⠟⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⡇⡁⠀⠀⠀⡁⡁⢀⢀⠀⠀⡄⢸⣿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⣿⣾⣾⣿⣷⣿⣿⣾⣿⣿⣿⣾⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡿⠿⠿⠿⠿⠟⠛⠛⠛⠻⠿⠿⠿⠃⠀⠀⠀⠀⠀⠀
                        --Anubhab
                            V 1.0
    """)
    main()