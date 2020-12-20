from hashlib import sha512
import base64
import binascii

subkeys=[] #a different subkey (key derived from the real key) is used each round to make extraction of the real key through cryptanalysis more difficult
rounds=2 #number of times the plaintext goes through the algorithm

def generateSubkeys(key, rounds): 
	for x in range(rounds): #create a subkey for every round
		subHash=sha512(key+str(x)).hexdigest() #creates a new subkey by appending a different number to each and hashing it
		subkeys.append(oct(int(subHash, 16))[2:]) #appends the subkey to the subkeys list in oct format
	print "subkeys: "+str(subkeys)
	
def padBinary(binary, paddingLen): #makes sure binary strings have exactly 8 bits
	padding=""
	for a in range(paddingLen-len(binary)): #repeat for the difference between 8 and the current length
		padding+="0"
	return padding+binary
	
def rotateByte(rotatingNumber, rotationNumber): #rotates a byte #I may not need this function
	rotatedNumber = getBinary(rotatingNumber, 8)[int(rotationNumber)%8:] + getBinary(rotatingNumber, 8)[:int(rotationNumber)%8]
	return int(rotatedNumber, 2)
	
def rotateBits(plainText, subkey):############remember to strip the 0
	octPlainText=[]
	for a in plainText:
		octPlainText.append([])
	for characterIndex in range(len(plainText)):
		octCharacter = oct(plainText[characterIndex])
		for digit in octCharacter[1:]:
			octPlainText[characterIndex].append(digit)
	print octPlainText
	xoredPlainText=[]
	keyIndex=0
	for character in octPlainText:
		octCharacter=""
		for digit in character:
			octCharacter += oct( int(digit) ^ int(subkey[keyIndex%len(subkey)]) )[1:]
			keyIndex+=1
		xoredPlainText.append(int(octCharacter, 8))
	print plainText
	print xoredPlainText
	return xoredPlainText
	
def shuffleBlock(block, subkey): #shuffles the plaintext based on the subkey
	shuffledBinaryBlock=[[],[],[],[],[],[],[],[]] #because the subkey is in oct I have created 8 lists in a list. every bit gets put into the list dictated by the corresponding byte in the subkey
	binaryBlock=""
	for a in block: #converts to binary
		binaryBlock+=getBinary(a, 8)
	for a in range(len(binaryBlock)):#preforms shuffling
		shuffledBinaryBlock[int(subkey[a%len(subkey)])].append(binaryBlock[a])
	shuffledBlock=""
	for a in shuffledBinaryBlock:#makes shuffledBinaryBlock into a string instead of a list of lists
		for b in a:
			shuffledBlock+=b
	shuffledBlockList=[]
	for a in range(len(block)):#/len(block)):
		shuffledBlockList.append(int(shuffledBlock[a*8:(a+1)*8], 2)) #makes shuffledBlock into a list of integers
	return shuffledBlockList #returns the list of integers

def round(subkey, right): #function that messes up the right half before it is XORed with the left
	rightA = rotateBits(right, subkey)
	rightB = shuffleBlock(rightA, subkey)
	return rightB #return final obfuscation

def split(plainText): #splits the plaintext into two halves and pads with a nullbyte if plaintext is odd
	if len(plainText)%2==0: #if plaintext is even
		left = plainText[:len(plainText)/2]
		right = plainText[len(plainText)/2:]
	else:#if plaintext is odd
		plainText.append(0)
		left = plainText[:len(plainText)/2]
		right = plainText[len(plainText)/2:]
	return left, right #return both halves
	
def exclusiveOr(left, newRight): #makes left an exclusive or of right that has gone through the round function
	newLeft=[]
	for a in range(len(left)): #item by item
		newLeft.append(newRight[a]^left[a])
	return newLeft #returns new left

def encrypt(plainText, subkeys): #function that glues together most of the stuff
	left, right = split(plainText) #splits plaintext
	print("left: "+str(left)+" right: "+str(right))
	for x in range(rounds-1): #for the number of rounds minus 1
		newRight=round(subkeys[x][:-1], right) #run the round function (strip off the last character of the subkey because it's an 'L')
		left=exclusiveOr(left, newRight) #make left the exclusive or of the newRight
		left, right = right, left #switch left and right
		print("left: "+str(left)+" right: "+str(right))
	newRight=round(subkeys[rounds-1][:-1], right)#do the final round needed but without the switch at the end
	left=exclusiveOr(left, newRight)
	print("left: "+str(left)+" right: "+str(right))
	cipherText=left+right 
	print "cipher text " 
	print cipherText
	return cipherText #return ciphertext as a list of int

def getAscii(plainText): #converts plainText to a list of ascii integers
	asciiText=[ord(c) for c in plainText]
	return asciiText
	
def getBinary(decimal, padding): #convert to binary
	decimal = int(decimal)
	binary = ''
	if decimal == 0: decimal=0
	while decimal > 0:
		binary = str(decimal % 2) + binary
		decimal = decimal >> 1
	binary=padBinary(binary, padding) #pad binary so it has a length of 8
	return binary

def getKey(): #gets the key
  key=raw_input("key > ")
  return key

def getPlainText(file): #reads the input file
  plainTextFile=open(file, "r")
  plainText=plainTextFile.read()
  plainTextFile.close()
  return plainText #returns contents
  
def outputCipherText(cipherText, direction): #output
	if direction=="e": #if it is encrypting
		asciiCipherText=""
		for a in cipherText: #converts the list of integers that is cipherText to an ascii string
			asciiCipherText+=chr(a)
		base64CipherText = base64.b64encode(asciiCipherText) #converts the ascii string to base 64
		return base64CipherText #returns base 64 encoded cipher text
	else: #if decrypting
		asciiPlainText = ""
		for a in cipherText: #converts the list of integers that is cipherText to an ascii string
			if not chr(a)==chr(0): #as long as it's not a nullbyte which we used to pad
				asciiPlainText+=chr(a)
		return asciiPlainText #return plaintext
	
def encryptOrDecrypt(asciiPlainText): #get direction
	direction=raw_input("encrypt (e), or decrypt (d) > ")
	return direction

def main(plainText, key, direction):
  asciiPlainText = getAscii(plainText)#get list of the characters in their ascii decimal form
  print asciiPlainText
  generateSubkeys(key, rounds)#generate subkeys based on key
  if direction=="e": #if encrypting
    cipherText = encrypt(asciiPlainText, subkeys) #encrypt plaintext
  else: #if decrypting
    asciiPlainText = getAscii(base64.b64decode(plainText)) #decode from the base 64 format
    cipherText = encrypt(asciiPlainText, list(reversed(subkeys))) #encrypt with the subkeys reversed (so decrypt)
  return outputCipherText(cipherText, direction)