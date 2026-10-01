# CSEC201_Socket_Project_RFMP
Socket programming project implementing the Remote File Management Protocol (RFMP) in Python and C, with RSA/AES/Caesar encryption — CSEC-201 group project.

Work split: 

  ayham_server.py -> Ayham 
  
  ayham_client.py -> Abdulrahman al khatib
  
  packets.py -> Elie
  
  crypto_utils.py -> ELie
  
  ayham_client.c -> Khaled


## Compiling the C Client

The C client uses unencrypted RFMP communication.

On macOS or Linux, compile it with:

```bash
gcc -Wall -Wextra ayham_client.c -o ayham_client
```

Run the compiled client with:

```bash
./ayham_client
```

Enter the server IPv4 address when requested. Use `127.0.0.1` when the server is running on the same computer.
