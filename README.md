# Password-Manager
A full stack Golang password manager that uses a CLI Golang frontend, a Golang backend, and MongoDB database. This is the frontend portion of a 2 part Password Manager Web app. The backend of this web server can be found [here](https://github.com/zacharyLYH/Password-Manager-Server).

# Just another iteration of a password manager? 
Kinda. The motivation behind this project was personal; I was looking for a free web hosted password manager but the ones I found that were web hosted required a monthly subscription. While it is indeed just another password manager, the intention of this project is to build an open source, web hosted, and most importantly ***secure*** password manager. If a password manager is not so much what you desire, with the way this project is built you may extrapolate the secure features of this project to build whatever you need - digital notes, a digital vault etc. 

# Disclaimer
I will not be providing a usable database instance. The reason is that while the design is sound, it is probable there are means of attack that I'm not aware of, and giving access to my MongoDB instance might be dangerous for the security of my passwords. However, I will link a good tutorial on how to get a MongoDB instance set up for your use. I will also not be providing the URL for accessing my hosted server, due to the fear of folks spamming requests and racking up my server costs. I will also link a good tutorial on setting a server youself. That said, anybody that adopts my implementation for their own password managing needs is liable for any theft of property happening to them. Keep your network and your access keys safe, and adapt this code to further enhance your security needs. 

# High level overview 
Roughly speaking, this project takes great inspiration from the SSH protocols. On a high level, this is the intended flow of the service:
1) Users log in and sends credentials over using RSA encryption
2) Server receives log in information, and upon succesful authentication sends back an encrypted Symmetric Key
3) Here on out any communication between parties utilizes this Symmetric Key

The frontend is a Golang CLI app. A user is expected to interact with the CLI app using a set of commands we'll define later. The backend is a Go server, nothing much to talk about there. The database we're using is a MongoDB database, and we'll use of 3 types of documents, a SymMap, UserData, and Password document. 

Now, we'll discuss the various functions and implementation detail on each end and the database design, and go on tangents at appropriate moments to further explain details or discuss security features.

# Key terms
- ttl : The time to live variable. Stored on the frontend. This is an approximation of a session cookie, where we'll time out the service and perform necessary clean ups to avoid memory leakage. Initially 0. 
- symKey : A secret symmetric key that will be previously exchanged by the client and server. 
- serverPubKey : The Golang backend server's public key. Used by the CLI app to perform RSA encryption before a symKey is produced. 
- desktopPub : The CLI app's public key.
- desktopPriv : The CLI app's private key
- username : The username of this user on this app. This field is unique for all accounts, thus works well as an identifier.
- storedUsername : The username we're logged in as, stored on the frontend. Is also meant to be used to emulate the use of a cookie. Initially an empty string. 
- serverSalt : A private string of characters stored on the server that will be used as salt for data that requires salting.
- id : For any user User, an id is a counter from 1 till the number of Password documents this User has, that acts as an easy identifier for both the client and server to refer to a particular Password document. 
- AES : A commonly used symmetric encryption algorithm. In this implementation, we'll be using some content as payload and a `symKey` as the hashing key. 
- RSA : An asymmetric encrypting algorithm. We'll be using RSA during the absence of `symKey`s, that is, before the symmetric key exchange. 

# Desktop side implementation
## Prerequisite
1) Pull the code from this repository, or run the frontend through this Docker command: ==insert when done==
2) If you chose the former, make sure you have Golang downloaded, and run `go run desktop.go`

By default, you'll should have the server's public key stored as `serverPubKey`. Recall that the code you're pulling does not come with a `serverPubKey` value, since you're not going to be using your own server. 

## Variables
- `symKey`
  - Secure session generated 32 byte symmetric key.
- `initSym`
  - Initial session generated 32 byte symmetric key. 
- `serverPub`
  - server's public key hard coded into a .pub file. 
- `nonce`
  - Since we'll be using GCM AES encryption, we'll need to provide a nonce value. This value will be provided on every API call by the frontend, incremented on the backend in the reply (if any).

### Welcome page 
- Prints some welcoming message
- Generates a public and private key, stored in `desktopPub` and `desktopPriv` respectively. 

### Sign up frontend
- Command: `signup <username> <password>`
  - No space seperation on username or password since this input is split on spaces
- Takes a `username` and `password`. 
- In a loop, make calls to the server to check if the `username` is available
  - Prompt for a new `username` if the name is not available
  - [API to call](###check-username-availability)
- Send to the server
  - Perform RSA encryption using the `serverPub` on the `password`, call it `signUpPassword`
  - `username` and `signUpPassword`
- Returns a success message if sign up worked
- Discussion
  - What happens to `signUpPassword`? On the backend, we'll use the private key and perform an RSA decryption to get the raw password
  
### Clear SymMap
- The backend uses a document called SymMap to map a username to a symKey. 
- The symKey is generated at log in time for all users, and stored in this map. When a user interacts with the server post login, the symKey needed for decrypting incoming traffic and reencrypting outbound traffic will be found in this map.
- If at any point the client exits their instance, whether due to a logout or a SIGTERM signal, it sends a clear SymMap request to remove that SymMap entry
- Takes `storedUsername`
- Outputs true on success and false otherwise
- More on its safety implications and periodic purging in the section on databases

### Exit or crash listener
- Listens for a SIGTERM and SIGKILL command
- When it does, it sends a `ClearSymMap` request to clear the SymMap entry
- Sends `storedUsername` to the `ClearSymMap` function

### Login
- Takes `username`, `password`, `initSym`,`nonce`, `serverPub`
  - Perform AES encryption using the `initSym` and `nonce` on the `password`, call it `loginPassword`
  - Perform RSA encryption on the `initSym` and `nonce` using `serverPub`, call this set of values `initialSecuritySet`
- Send `username`, `initialSecuritySet`, and `loginPassword` 
- Receive a `symKeyHash` on successful authentication
  - AES decrypt the `symKeyHash` using `initSym`. 
  - The result of this decryption is `symKey`
- If all the previous steps were successful
  - Set the `ttl` variable to the time right now. [ttl safety discussion here](###ttl)
  - Set `storedUsername` to the username passed in as `username`
- If any of the above steps were unsuccessful, send a [SIGTERM](###exit-or-crash-listener) command

### Check ttl
- Called before any other API's code can be executed. 
- Checks if the user has been logged in for more than 20 minutes, you may vary this number for your needs.
- It sends a [SIGTERM](###exit-or-crash-listener) command 

### Get all stored sites
- [Check ttl](###check-ttl) 
- Input `storedUsername`
- [Discussion](###**storedUsername**) on the safety of `storedUsername`
- Output is a string of id; description pairs, for all Password objects
  - For example: id1; description1; id2; description2
- These ids are sorted in in increasing order 

### Create a new Password entry
- [Check ttl](###check-ttl)  
- Input `siteUserName`, `password`, `description`, `storedUsername`
- Using the `symKey` gotten from [login](###login), encrypt the `siteUserName` and `password` field using JWT
  - `hashPassword` =  *aesEncrypt* (`password`, `symKey`)
  - `hashSiteUserName` = *aesEncrypt* (`siteUserName`, `symKey`)
- `description` must be filled. This is the description that the user will read to discern one Password object from another when the user tries looking for passwords later. 
- Send `hashSiteUserName`, `hashPassword`, `description`, `storedUsername`
- Output true on success false otherwise

### Update an entry
- [Check ttl](###check-ttl) 
- Input `siteUserName`, `password`, `description`, `storedUsername`, `id`
- At least one of `siteUserName`, `password`, `description` is required and `storedUsername`, `id` are required
- `id` can be retrieved from [Get all stored sites](###get-all-stored-sites)
- Using the `symKey` gotten from [login](###login), encrypt the `siteUserName` and `password` field using JWT
  - `hashPassword` =  *aesEncrypt* (`password`, `symKey`)
  - `hashSiteUserName` = *aesEncrypt* (`siteUserName`, `symKey`)
- `description` if left empty will take on the description during creation
- Send `hashsiteUserName`, `hashPassword`, `description`, `storedUsername`, `id`
- Output true on success false otherwise

### Get a password 
- [Check ttl](###check-ttl) 
- Input `storedUsername`, `id`
- `id` can be retrieved from [Get all stored sites](###get-all-stored-sites)
- Send `storedUsername`, `id`
- Output `receivedUsernameAndPassword` that needs to be JWT decrypted to obtain the raw password
  - rawOutput = *aesDecrypt*(`receivedUsernameAndPassword`, `symKey`)
  - raw username = rawOutput[0]
  - raw password = rawOutput[1]

### Delete a Password object
- [Check ttl](###check-ttl) 
- Input `storedUsername`, `id`
- `id` can be retrieved from [Get all stored sites](###get-all-stored-sites)
- Send `storedUsername`, `id`
- Output true on success false otherwise

## Safety of this design decision
### **storedUsername**
- It might be weird why we think storing such critical identification information as a global variable is safe, and safe from spoofing on the local device. Here are the reasons.
- This frontend is compiled, and while we don't do it in this implementation, it is understood that we only distribute binaries of our compiled code, and thus we're not succeptable to any malicious party injecting code into our application.
- We do not do this here, but a suggested way to mitigate the chance of a tampered version of this program is by way of checksums. Another engineer that would like to widely distribute this code should definitely implement a checksum system at run time before login, which should guarantee the integrity of the code before any work begins.  
- Notice also that the value stored in this variable **CANNOT** be changed after login - there is no changing into a different user after login has happened. 
- In general, if this variable is not empty ie. populated with a value, you may assume this user logged in correctly, and has full access to whatever `storedUsername` has access to.

### **ttl**
- The previous criticism can be made here as well and the same response will be provided.

### Is hard coding the server's public key into a variable safe?
- There shouldn't be an issue, as it is a public key; we're not really afraid of someone finding out our public key, since that is public information anyway. 
- In any event, unless the binary is decoded, this key is not readable from the program's execution.

