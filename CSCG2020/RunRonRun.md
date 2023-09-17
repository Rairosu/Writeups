The challenge provided me with the python code for the service.
After reading through it, I saw that it asks for a number x between 0 and the length of the flag, removes the first x characters from the flag, encrypts the resulting string with RC4 and a 16 byte long random key and returns the result of the encryption.
```py
def roncrypt_flag(offset):
    key = os.urandom(16)
    cipher = ARC4.new(key)
    return cipher.encrypt(FLAG[offset:])
```
The RC4 algorithm uses the 16 byte key to generate a keystream which is then xored with the plaintext to create the ciphertext.
While reading the Wikipedia article about RC4 a bit more, I noticed the strong second byte bias of the keystream generation algorithm of RC4:
> The best such attack is due to Itsik Mantin and Adi Shamir who showed that the second output byte of the cipher was biased toward zero with probability 1/128 (instead of 1/256).

Together with the ability to give the service an offset I was able to create an exploit to recover the flag from the given ciphertext. 
 I requested the flag with the same offset multiple times, took the second character from the output and calculated which character had the highest probability of occuring in the output. Because the second byte of the keystream has a bias towards zero and $x \oplus 0 = x$, the calculated character should be the correct character in the flag. Obviously, the more encrypted flags we get, the more reliable the exploit gets (I personally used `24000` requests but it should work with much less as well). Doing this for all possible offsets, we get: `SCG{schnieke}`, but we are missing the first character. Luckily for us, we know that the format of the flags is: `CSCG{xxx}` so it is clear that the first character is a `C`  which gives us the flag:

`CSCG{schnieke}`
