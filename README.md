-----------------------------------------------------------------------------------------
<b>Code flow:</b>
-----------------------------------------------------------------------------------------
<b>main():</b>
This gets called first. This tries to get the status code, response body and the redirectURL if its present from the connect() function passing the Method and the URL as parameters.
if the status code returned is 3xx, the main calls the connect() function in a while loop with the redirectURL up to 5 times.
The final exitCode is set based on the status code and does a sys.stdout.write(body) to print the body and then sys.exit(exitCode) for being able to echo the $? with the right value.

-----------------------------------------------------------------------------------------
<b>connect(method, URL):</b>
This function opens a socket, creates a response header using getResponseHeader() and send it to the analyzeHeader() method which returns the isChunked, isGzip flags and the status code, contentLength (if present else 0) and the redirectURL (if present else ‘’). 
Then if chunked then it handles chunk data till we get a 0 size chunk, else gets from content length. 
Then if the data is zipped the decompressData() function decompresses the data and finally the (statusCode, message, data, redirectURL) is sent to main after the connection is closed.

-----------------------------------------------------------------------------------------
<b>getResponseHeader(conn), analyzeHeader(header):</b>
This function takes in a socket and does a .recv(1) (one byte at a time) till we receive two CRLF (as per spec) and send the header data to analyzeHeader, which parses the header for the flags and data mentioned above then returns to the connect method.

-----------------------------------------------------------------------------------------
<b>getNextChunkSize(conn), getDataFromChunk(conn, chunkSize):</b>
This function takes the socket conn as input and asks for data with recv(1) till we get a CRLF then it converts this Hex string to int value and returns the chunk size. 
The getDataFromChunk() function gets called and this does a .recv() until the number of bytes equal to the chunk size is obtained and returns the data.

-----------------------------------------------------------------------------------------
<b>getContent(contentLength, conn):</b>
If we have a content-length from the analyzeHeader() then this gets function gets called and does a .recv() until the content length of bytes have been received.

-----------------------------------------------------------------------------------------
<b>decompressData(data):</b>
This function gets called if the analyzeHeader() returned the isGzip as 1. This decompresses the data that was received.
