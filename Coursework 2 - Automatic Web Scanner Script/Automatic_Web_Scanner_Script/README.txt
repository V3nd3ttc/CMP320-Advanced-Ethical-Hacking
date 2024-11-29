Script was ran on latest Kali Linux version at the time:
- "Kali Rolling (2023.1) x64 2023-03-10"
=======================================================
In order to save file to pdf LibreOffice must be installed. This can be done by running:
- "sudo apt install libreoffice"
=======================================================
To install the python requirements for the script run:
- "pip install -r requirements.txt"
=======================================================
To run the script use:
- "python3 script.py -T <target>"
Target must be provided for the script to start running
=======================================================
Link to TryHackMe rooms on which the script was tested:
- https://tryhackme.com/room/picklerick
- https://tryhackme.com/room/toolsrus
=======================================================
To show some of the functionality of the script without using the TryHackMe rooms run the following command:
- "python3 script.py -T 10.10.156.12 -O". This will use the folder of the output received after running the tools and bruteforcing the Pickle Rick room in the provided video to create the report.
- "python3 script.py -T 10.10.239.111 -O". This will use the folder of the output received after running the tools and bruteforcing the ToolsRus room in the provided video to create the report.
=======================================================
Video of the script being executed on a freshly booted Kali Linux virtual machine has been provided with the rest of the submission
=======================================================
