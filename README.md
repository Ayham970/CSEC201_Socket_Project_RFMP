# CSEC201_Socket_Project_RFMP
Socket programming project implementing the Remote File Management Protocol (RFMP) in Python and C, with RSA/AES/Caesar encryption — CSEC-201 group project.

Work split: 

  ayham_server.py -> Ayham 
  
  ayham_client.py -> Abdulrahman al khatib
  
  packets.py -> Elie
  
  crypto_utils.py -> Elie
  
  ayham_client.c -> Khaled


## How to Run the Project

### 1. Install the requirements

Check `requirements.txt` for the required libraries.

On Kali Linux:

```bash
pip install cryptography --break-system-packages
```

### 2. Start the server

Open a terminal in the project folder and run:

```bash
python3 ayham_server.py
```

It prints `RFMP server listening on port 5050`. Keep this terminal open.

Always run the Python files with `python3`. Running `./ayham_server.py` makes the shell treat the file as a shell script.

### 3. Run the Python client

Open a second terminal in the project folder and run:

```bash
python3 ayham_client.py
```

The client asks for:

1. **Server IP**: press Enter for `127.0.0.1` (same computer), or type the server's IP address.
2. **Mode**: `NONE` (no encryption), `AES`, or `CAESAR`.
3. **Username**: only asked for `AES` and `CAESAR`.

Then choose from the menu:

| Option | What it does |
| --- | --- |
| 1. Run a command | Sends a command such as `mkdir test`, `cd test`, `ls`, `ren old new` |
| 2. Read a file | openRead: shows a file from the server |
| 3. Write a file | openWrite: sends a local file to the server |
| 4. End | Closes the connection |

Commands: `mkdir`, `cd`, `rmdir`, `rd`, `del`, `ren`, `ls`, `pwd`, `whoami`, `hostname`, `date`. Names cannot contain spaces.

Server errors are shown as `Server error <code>: <description>`.

### 4. Run the C client



Enter the server IPv4 address when requested. Use `127.0.0.1` when the server is running on the same computer.

### Running on different computers

1. All computers must be on the same network (a phone hotspot works best).
2. On the server computer, find its IP address with `ip a` (Linux) or `ipconfig` (Windows), for example `192.168.1.5`.
3. Start the server on that computer.
4. On the other computers, enter that IP address when the client asks for the server IP.
