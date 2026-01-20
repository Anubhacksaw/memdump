MemDump 📱🔍

Professional Android Memory Forensics & Analysis Tool

MemDump is a powerful, production-grade Python utility designed for mobile security assessments and penetration testing. It leverages Frida to perform deep memory introspection of running Android applications, dumping raw memory segments and extracting sensitive strings (passwords, tokens, API keys) in real-time.
🚀 Key Features

    ⚡ Turbo Mode Extraction: Utilizes Multiprocessing to extract strings using 100% of available CPU cores, making it significantly faster than standard methods.

    🛡️ Crash-Proof Dumping: Implements smart "chunking" (1MB blocks) to prevent Frida pipe crashes when dumping large heap sizes (500MB+).

    🧹 Auto-Cleanup: Automatically manages and deletes thousands of temporary binary chunks, leaving you with just the clean output file.

    📝 Full Logging: Supports detailed debug logging to file (--log) for troubleshooting and audit trails.

    🎯 Regex Filtering: Built-in extraction engine filters out garbage data, retaining only readable ASCII/Unicode strings (tokens, credentials, PII).

📋 Prerequisites

    Python 3.x

    Frida Server running on the target Android device (Rooted).

    ADB (Android Debug Bridge) connected and authorized.

Installation

    Clone the repository:
    Bash

    git clone https://github.com/yourusername/memdump.git
    cd memdump

    Install dependencies:
    Bash

    pip install -r requirements.txt

🛠️ Usage

Make sure your Android device is connected via USB and the target app is running.
1. Basic Scan (Recommended)

Dumps memory, extracts strings to a text file, and cleans up temporary binaries.
Bash

python memdump.py -p "com.example.bankingapp" -o secrets.txt

2. Keep Raw Binary Files

If you want to perform manual analysis (e.g., using a Hex Editor) on the raw memory dumps later.
Bash

python memdump.py -p "App Name" -o output.txt --keep-bin

3. Debug Mode

Save a detailed log of the entire extraction process for troubleshooting.
Bash

python memdump.py -p "App Name" -o output.txt --log debug_dump.log

⚙️ Command Line Arguments
Argument	Description	Required
-p, --package	The target App Name or Package ID (e.g., com.facebook.katana).	Yes
-o, --output	The filename for the final extracted text report.	Yes
--log	Path to save a detailed debug log file.	No
--keep-bin	Flag to skip deletion of raw .bin dump files after extraction.	No
🧪 Example Workflow

    Launch the Target App: Open the banking app on your rooted device.

    Run MemDump:
    Bash

    python memdump.py -p "Target Bank" -o bank_dump.txt

    Analyze Results: Open bank_dump.txt and search for sensitive keywords:

        Bearer (Auth Tokens)

        password / pin

        eyJh (JWT Tokens)

        BEGIN PRIVATE KEY

⚠️ Disclaimer

This tool is for educational purposes and authorized security testing only. Do not use this tool on applications or devices you do not own or do not have explicit permission to test. The author is not responsible for any misuse.

Happy Hacking! 🕵️‍♂️
