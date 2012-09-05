# SimpleTftpServer

A really simple TFTP server. Works like SimpleHTTPServer and serves files in the current working directory.

Handy for uploading files to routers or transferring files across a network.

## Installing

```
python setup.py install
```

## Using

Change to the directory containing the files you want to serve. Then run the following command.

```
python -m SimpleTftpServer [address [port]]
```

If you don't specify an address or port to bind to, they will default to "0.0.0.0" and 69 respectively.

## Note

Privileges are not dropped after binding. Therefore, this is not recommended for production usage.

To keep server implementation simple, this does not allow for much network interruptions or similar. It does not resend packets nor timeout.