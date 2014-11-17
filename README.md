#Hooking Private Code from Stripped iOS Binaries

As far as the scanner is concerned, I'm finished with it. I'm going to do a final sweep and remove superfluous code and then I'll land the final commit.

Contact: `wiresharkGD@gmail.com` || `@Hexploitable`

##Instructions

1. Open your target app in a disassembler, grab first ~16 bytes (customise this as you will) of the method you want to hook and then use these as the signature with the scanner.

2. Compile the scanner and then set the binary's entitlements appropriately:

		ldid -Sentitlements.xml <scanner binary>
3. Write the needle to a file:

		echo -n -e '\x55\x48\x89\xE5\xB8\x15\x00\x00\x00\x5D' > hex

4. Run the scanner against the target process. It will locate the signature in memory and print it's address. The signature has to be passed in as bytes, not a literal string so use the scanner as shown:

		sudo ./scanner <pid> <Path to file containing needle>
e.g:

		sudo ./scanner 1337 ./hex

5. Use the returned address in Tweak.xm to hook it.
	-	If ASLR/PIE is enabled - simply get the address of an import too, calculate the offset and then modify Tweak.xm to use an offset instead of a hardcoded address, this way you can hook it, knowing it'll work 100% of the time. 


6. Inject your library into the process as you normally would:

		DYLD_INSERT_LIBRARIES=/Library/MobileSubstrate/DynamicLibraries/<libName>.dylib ./<binary>
