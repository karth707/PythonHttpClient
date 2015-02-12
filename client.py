#!/usr/bin/python -tt
#
# Created by: 
# Kartheek Ganesh Nallepalli
# Arizona State University
#
# Part of coursework for CSE 591: Security and Vulnerability Analysis

import sys
import socket
import urlparse
import re
import gzip
import StringIO

def createRequestHeader(method, host, path):                                    
  # Building the request header based on RFC specs and a sample Mozilla header   
  requestHeader = method + ' ' + path + ' ' + 'HTTP/1.1\r\n'
  requestHeader = requestHeader + 'Host: ' + host + '\r\n'
  requestHeader = requestHeader + 'Accept: text/html;q=0.9,*/*;q=0.8\r\n'
  #requestHeader = requestHeader + 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
  #requestHeader = requestHeader + 'Accept-Language: en-us,en;q=0.5\r\n'  
  requestHeader = requestHeader + 'Accept-Encoding: gzip\r\n\r\n'
  #requestHeader = requestHeader + 'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n'
  #requestHeader = requestHeader + 'Keep-Alive: 300\r\n'
  #requestHeader = requestHeader + 'Connection: keep-alive\r\n\r\n'      
  return requestHeader  

def getHostPath(URL):
  urlObject = urlparse.urlparse(URL)  
  host = urlObject.netloc
  path = urlObject.path
  port = urlObject.port
  if path == "":
    path = "/"
  if port == None:
    port = 80
  else:
    host = re.split(':',host)[0]                  
  return (host, path, port)      

def getConnection(host, port, requestHeader):
  try:    
    con = socket.create_connection((host,str(port)))    
    con.settimeout(3)
    con.send(requestHeader)    
  except Exception,e: 
    print str(e)  
    print "Ouch! Error while connecting to host..."
  return con

def movePrevThree(array):
  array[0] = array[1]
  array[1] = array[2]
  array[2] = array[3]
  array.pop()
  return array

def prevThreeCheck(array):
  #print str(array) + '; length=' + str(len(array))
  if len(array) != 3:
    return False
  else:
    if array[0] == '\r' and array[1] == '\n' and array[2] == '\r':
      return True
    else:
      return False

def getResponseHeader(conn):
  header = ''
  prevThree = []
  while 1:
    byte = conn.recv(1)    
    if len(byte) != 1:
      continue
    else:
      header = header + byte 
      check =  prevThreeCheck(prevThree)                
      if byte == '\n' and prevThreeCheck(prevThree):                  
        break
      prevThree.append(byte)      
      if len(prevThree) == 4:        
        prevThree = movePrevThree(prevThree)        
  return header  
  
def analyzeHeader(responseHeader):   
  contentLength, isChunked, isGzip = 0, 0, 0
  statusCode, message, redirectURL = '', '', ''
  sLine = 0  
  headers = re.split('\r\n', responseHeader)
  for header in headers:
    if header == '':
      continue
    if sLine == 0:
      statusLine = re.split(' ', header)      
      (statusCode, message) = (statusLine[1], statusLine[2])
      sLine = 1
    else:
      splitHeader = re.split(':', re.sub(' ', '', header, 1))
      #print splitHeader
      if splitHeader[0] == 'Content-Length':
        contentLength = int(splitHeader[1])
      elif splitHeader[0] == 'Transfer-Encoding' and splitHeader[1] == 'chunked':
        isChunked = 1
      elif splitHeader[0] == 'Content-Encoding' and splitHeader[1] == 'gzip':
        isGzip = 1
      elif splitHeader[0] == 'Location':
        redirectURL = splitHeader[1] + ':' + splitHeader[2]  
  #print (statusCode, message, contentLength, isChunked, isGzip, redirectURL)  
  return (statusCode, message, contentLength, isChunked, isGzip, redirectURL)

def getNextChunkSize(conn):
  chunksize = ''
  prevByte = ''
  while 1:    
    byte = conn.recv(1)    
    if len(byte) != 1:
      continue
    else:
      chunksize = chunksize + byte
      if byte == '\n' and prevByte == '\r':
        break
      prevByte = byte          
  hexBytes = re.sub('\r\n', '', chunksize)   
  return int(hexBytes, 16)

def getDataFromChunk(conn, chunkSize):  
  chunkData, crlf = '', ''
  #print 'chunk size expected: ' + str(chunkSize)  
  while chunkSize > 0:
    data = conn.recv(chunkSize)
    chunkData = chunkData + data
    chunkSize = chunkSize - len(data)
  while len(crlf) != 2:
    crlf = crlf + conn.recv(1)  
  #print 'chunkDataLengthCheck: ' + str(len(chunkData))
  #print 'crlf length check: ' + str(len(crlf))
  return chunkData
  
def decompressData(data):
  out = StringIO.StringIO(data)
  decompressedFile = gzip.GzipFile(fileobj=out, mode='rb')
  read = decompressedFile.read()        
  data = str(read)
  return data    
 
def getContent(contentLength, conn):  
  contentData = ''
  #print 'contentLength expected: ' + str(contentLength)
  while contentLength > 0: 
    data = conn.recv(contentLength)     
    contentData = contentData + data
    contentLength = contentLength - len(data)     
  #print 'contentLength received: ' + str(len(contentData))
  return contentData  
  
def connect(method, URL):  
  data = ''
  (host, path, port) = getHostPath(URL)  
  requestHeader = createRequestHeader(method, host, path)  
  conn = getConnection(host, port, requestHeader)      
  responseHeader = getResponseHeader(conn)
  (statusCode, message, contentLength, isChunked, isGzip, redirectURL) = analyzeHeader(responseHeader)        
  # append chunks
  while isChunked == 1:
    chunkSize = getNextChunkSize(conn)    
    if chunkSize == 0:
      break    
    data = data + getDataFromChunk(conn, chunkSize)
  
  # if only content - length and no chunked data              
  if contentLength > 0:
    data = data + getContent(contentLength, conn)  
  
  # if compressed
  if isGzip == 1:
    data = decompressData(data)
    
  conn.close()            
  return (statusCode, message, data, redirectURL)

def getExitCode(statusCode):  
  code = 0    
  if statusCode[0] == '2':
    return code
  elif statusCode[0] == '5':
    return  5
  elif statusCode[0] == '4':
    return 4  
  elif statusCode[0] == '3':
    return 3
  else:
    return 1

def main():      
  method = sys.argv[1]  
  URL = sys.argv[2]
  try:
    (statusCode, message, responseBody, redirectURL) = connect(method, URL)    
        
    # handle redirects  
    redirectCount = 0  
    while statusCode[0] == '3':            
      if redirectCount == 5:
        break
      sys.stdout.write("Redirecting to: " + redirectURL) 
      (statusCode, message, responseBody, redirectURL) = connect(method, redirectURL)      
      redirectCount += 1
    
    # Print the response body
    sys.stdout.write(responseBody)
    
    exitcode = getExitCode(statusCode)
    sys.exit(exitcode)  
  except Exception,e: 
    print str(e)
    sys.exit(1) 


if __name__ == '__main__':
  main()