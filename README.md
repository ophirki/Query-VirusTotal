# Query-VirusTotal
Server:
A Simple asynchronous server that implements POST request method.
The server should be able to receive files from the client(s) using the POST method:
  - Save the file locally
  - Scan the file automatically using https://www.virustotal.com/ API, and return the results
    to the Client in a JSON format

Client:
Create a PowerShell script that uploads the content of an executable file to your Python server
The script should be able to get the executable file using 2 modes:
  - Receive the path of an executable as an input from the user
  - Find the process that consumes the highest CPU percentages, and find its executable
The script then parses the JSON response returned by your Python server and displays
whether this file is dangerous or not. 

Don't forget to add your Virus Total api-key
