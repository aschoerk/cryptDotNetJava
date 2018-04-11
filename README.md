# cryptDotNetJava

This project is an example how the encrypted transfer of files between a dotNet (C#) environment and Java might be handled, based on asymmetric encrpytion.

Since the used RSA-Algorithm is only able to encrypt fixed length data in one go, the procedure is combined with a symmetric (AES keylength 256) encryption.


## Files

* privateKey.xml: an example private key in xml RSAKeyValue-Format
* publicKey.xml: an example public key in xml RSAKeyValue-Format
* Encryptor.cs: contains the encryption able to encrypt byte-Arrays of arbitrary length
* EncryTest.cs: contains a unit-test starting with the encryption of a JPG using the public key and testing the decryption afterwards.
* example.jpg: the file to be encrypted
* example.encrypted: the encryption result

## Procedure

### Keyencryption

First an AES-Key is generated. The two components, the actual key and the initialisation value are afterwards put into a bytearray  

* length of the key (1 Byte)
* length of the iv (1 Byte)
* the key (keylen Bytes)
* the iv (ivlen Bytes)

this array is encrypted using the RSA public key stored in publicKey.xml

The result is stored in a bytearray

### payload encryption

The file is read, the result is a bytearray.
This bytearray is encrypted using the AES-Key. The result is stored as 
bytearray.

### creation of the resultfile

A further bytearray is created.

* the lower significant byte of the length of the encrypted AES Key Array
* the higher significant byte of the length of the encrypted AES Key Array
* the actual encrypted key as it is encrypted using the public key
* the actual encrypted payload as it is encrypted using the AES key

