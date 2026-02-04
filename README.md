\# HYPERION: THE OBSIDIAN MONOLITH



\### The Last Password Manager You Will Ever Need.



> \*\*TRUST NO ONE. AUDIT EVERYTHING.\*\*



---



\## THE MANIFESTO



Standard password managers are broken.



\* \*\*Cloud Managers (LastPass, 1Password):\*\* They store your "encrypted" vault on \*their\* servers. One breach, one zero-day in their web app, and your life is leaked.

\* \*\*Browser Managers (Chrome, Edge):\*\* They are notorious for weak local encryption. Malware steals `Login Data` files daily.

\* \*\*Standard Crypto:\*\* Most managers rely on AES-256 and PBKDF2. While "standard," PBKDF2 is computationally cheap for GPUs. A hacker with a rig of RTX 4090s can try \*\*billions\*\* of passwords per second against your vault.

\* \*\*The OS Trap:\*\* Most apps rely on `/dev/urandom` or `BCryptGenRandom`. If the OS vendor (Microsoft/Apple) or the hardware (Intel/AMD) has a backdoor in the RNG (Random Number Generator), your encryption keys are predictable.

\* \*\*YOUR OS IS COMPROMISED - DO NOT TRUST HARDWARE-PRIMITIVE CRYPTOGRAPHY

\*\*HYPERION rejects these compromises.\*\* We do not trust the cloud. We do not trust the OS. We do not trust the hardware. We rely on \*\*Math\*\* and \*\*Physics\*\*.



---



\## SECURITY ARCHITECTURE



Hyperion is not just "secure." It is \*\*hostile\*\* to attackers.



\### 1. Titan-KDF (The GPU Killer)



Standard vaults use PBKDF2-SHA256. It is fast. That is the problem.

Hyperion uses \*\*Titan-KDF\*\*, a custom memory-hard key derivation function.



\* \*\*64MB Memory Grid:\*\* To verify \*one\* password, Hyperion fills a 64MB grid of RAM with chaotic data.

\* \*\*Serial Dependency:\*\* Every byte generated depends on the previous byte.

\* \*\*Why this matters:\*\* GPUs have thousands of cores but limited RAM per core. They rely on speed, not memory capacity. Titan-KDF forces an attacker to use 64MB of RAM for \*every single guess\*. This reduces GPU cracking speeds from \*\*billions/sec\*\* to \*\*dozens/sec\*\*.



\### 2. XChaCha20-Poly1305 (The Void Cipher)



We do not use AES. We use \*\*XChaCha20\*\*.



\* \*\*192-bit Nonce:\*\* Standard AES-GCM uses a 96-bit nonce. If an RNG glitch occurs, nonce reuse can break the encryption. XChaCha20 uses a 192-bit nonce. The odds of a collision are lower than the odds of a meteor hitting your CPU at this exact second.

\* \*\*Poly1305 Integrity:\*\* We use a cryptographic MAC (Message Authentication Code). If a single bit of your vault file is tampered with (by malware or disk rot), Hyperion will refuse to decrypt it. We do not serve corrupted data.



\### 3. Biological Entropy Harvesting



We do not trust `rand()`.



\* \*\*The Ritual:\*\* When you initialize Hyperion, you must "mash keys."

\* \*\*The Science:\*\* We measure the \*\*nanosecond\*\* timing differences between your keystrokes. We mix the key value, the time delta, and a rotating buffer to seed our internal CSPRNG (Cryptographically Secure Pseudo-Random Number Generator).

\* Your nervous system provides the entropy. The NSA cannot backdoor your own muscle reflexes.



\### 4. Volatile Memory Hygiene



When you close Hyperion, we don't just `free()` memory. We use `secure\_wipe()` to overwrite all sensitive RAM (keys, passwords, the memory grid) with zeros using volatile pointers to prevent compiler optimization.



---



\## COMPILATION



Hyperion is written in \*\*Pure C (C99)\*\*. Zero external libraries. No `npm install`. No `pip`. No bloated dependencies.



\### Prerequisites



\* \*\*GCC\*\* (MinGW for Windows, standard GCC for Linux/Mac).



\### Windows



Open your terminal (cmd/PowerShell) and run:



```powershell

\# Compile the Vault

gcc hyperion\_v5.c -o hyperion.exe -O3



\# Compile the Chrome Importer (Bridge)

gcc hyperion\_bridge.c -o bridge.exe -O3



```



\*Note: `-O3` is critical. It optimizes the heavy math so it runs fast for you, but the algorithm remains mathematically complex.\*



\### Linux / macOS



```bash

\# Compile the Vault

gcc hyperion\_v5.c -o hyperion -O3



\# Compile the Chrome Importer (Bridge)

gcc hyperion\_bridge.c -o bridge -O3



```



---



\## HOW TO USE



\### 1. The Initialization Ritual



Run `./hyperion`.



1\. You will be asked to \*\*MASH KEYS\*\*.

2\. Do not hold a key down. Type randomly. Smash the keyboard.

3\. The bar `\[#####.....]` represents the entropy pool filling up.

4\. Once full, the internal RNG is seeded with your biological chaos.



\### 2. Managing Passwords



\* \*\*\[A]dd Entry:\*\* \* Enter Site and User.

\* \*\*Chaos Generator:\*\* Press 'y' to generate a password. Watch the bar fill as you provide entropy for \*that specific password\*.





\* \*\*\[L]ist:\*\*

\* View all sites.

\* Enter an ID to decrypt and reveal.

\* \*\*Security Feature:\*\* The password remains visible until you press \*\*ESC\*\* or \*\*ENTER\*\*. This prevents "shoulder surfing" or leaving it on screen accidentally.





\* \*\*\[Q]uit:\*\*

\* Encrypts the database.

\* Wipes RAM.

\* Saves to `hyperion.vault`.







\### 3. Usage Arguments



By default, it looks for `hyperion.vault`. You can specify a different file:



```bash

./hyperion my\_secret\_usb.vault



```



---



\## 🌉 THE BRIDGE (Import from Chrome)



If you are currently using Google Chrome, Edge, or Brave, your passwords are insecure. Migrate them immediately.



1\. \*\*Export:\*\* Go to Chrome Settings -> Passwords -> Export Passwords (save as `.csv`).

2\. \*\*Run Bridge:\*\*

```bash

./bridge passwords.csv



```





3\. \*\*Encrypt:\*\*

\* The Bridge will parse your insecure CSV.

\* It will ask for a \*\*Master Password\*\*.

\* It runs the \*\*Titan-KDF\*\* engine to harden the data.





4\. \*\*Finalize:\*\*

\* It produces `imported.vault`.

\* \*\*DELETE THE CSV FILE IMMEDIATELY.\*\* Use a secure delete tool (like `shred` on Linux) if possible.





5\. \*\*Login:\*\*

\* Run `./hyperion imported.vault`.







---



\## ⚠️ AUDIT \& DISCLAIMER



\*\*Cryptographic Primitives Used:\*\*



\* \*\*Stream Cipher:\*\* XChaCha20 (Extended Nonce ChaCha20)

\* \*\*MAC:\*\* Poly1305 (One-time authenticator)

\* \*\*KDF:\*\* Titan-KDF (Custom 64MB Scrypt/Argon2 hybrid variant using ChaCha20 mixing)

\* \*\*RNG:\*\* User-Seeded ChaCha20-DRBG



\*\*Disclaimer:\*\*

\*This software is provided "as is", without warranty of any kind. While the algorithms used are mathematically robust and the implementation is paranoid, true security is a process, not a product. If you lose your Master Password, your data is gone forever. There is no "Forgot Password" button. The math makes recovery impossible.\*



\*\*Welcome to the resistance.\*\*

