---
layout: category-post
title: "Hundter's Keylogger"
date: 2016-10-18T00:00:00-05:00
---

### Introduction

Tying malware back to its earlier versions gives us the ability to look at more rudimentary versions of the code. The versions where the malware writer was just trying to see if all their tricks worked before doing their best to hide them. We came across a small keylogger that was missed by over 90% of anti-virus engines (5/56 on virustotal).  What caught our eye most was that this sample still had a lot of debugging output and hardcoded values in it, which led us to believe that it’s an early version of what might turn out to be a fully fledged keylogger.

<figure>
<img src="/images/Hundter01.jpg">
</figure>

The malware contained several interesting strings that hinted at its functionality as well as a unique build path string:

```
C:\Users\Hundter\Documents\Visual Studio 2015\Projects\NewRat\obj\x64\Debug\kstat.pdb
```

The name “Hundter” will continue to be a common thread throughout this write-up.


### Commands:

The main function that parses arguments has support for the following commands:

|Command|Description|
|-----|-----|
|TAKE_SCREENSHOT|Take a screenshot, calling graphics.CopyFromScreen and formatting as a jpg|
|DESKTOP_STREAM_ENABLE|Sends a continuous series of low quality screenshots while sleeping 180 milliseconds|
|DESKTOP_STREAM_DISABLE|Disable screen streaming|
|DESKTOP_STREAM_STATUS|Returns if the stream is alive or not|
|KEYLOGGER_ENABLE|Starts the keylogger|
|KEYLOGGER_STATUS|Returns if the keylogger is alive and length of the keylogged file|
|KEYLOGGER_DISABLE|Disables the keylogger|
|KEYLOGGER_DUMP|Sends the raw bytes of the keylogged file over the socket|
|MIGRATE_PROCESS_LIST|Returns a list of running processes|
|MIGRATE_PROCESS|Migrates the existing process into the context of another process|
|UPDATE_REMOTE_BACKDOOR|Writes a new file, starts it and kills the existing process|
|EXIT_CLIENT|Shuts down the socket and closes communication|

### Persistence:

The keyloggers persistence is set up through the common CurrentVersion\Run key

<figure>
<img src="/images/Hundter02.jpg">
</figure>

Setting the value of the key to “Microsoft kstat”.

### Keylogging:

The malware will set up a streamwriter to the file “log.hun” where it will store the keystrokes

<figure>
<img src="/images/Hundter03.jpg">
</figure>

It will append the date and then listen for keystrokes

<figure>
<img src="/images/Hundter04.jpg">
</figure>

The keyloggers main functionality is handled by a LowLevelKeyboardProc Hook and using typical API’s to set up this functionality.

<figure>
<img src="/images/Hundter05.jpg">
</figure>

### Process Migration / Injection:

There is code in the malware to migrate processes; it would appear that this is largely copied and pasted from tutorials on C# injection and migration.  The process injection currently does not work and has hardcoded references to files on the attackers desktop.

<figure>
<img src="/images/Hundter06.jpg">
</figure>

### Remote communications:

The remote IP address 78.46.74.130 is hardcoded into the backdoor for communications.  Before socket communication is established the keylogger will ensure that autorun key is in place before connecting.

<figure>
<img src="/images/Hundter07.jpg">
</figure>

Once the value is set, the address is parsed.

<figure>
<img src="/images/Hundter08.jpg">
</figure>

Interestingly enough, the application will write to STDOUT once it’s connected and then fall into a continuous loop to receive commands. 

<figure>
<img src="/images/Hundter09.jpg">
</figure>

### Sending Stream of the Desktop

The first thing of note about the function to send a remote stream is its use of a different port than the standard communication.  For streaming it uses 7778.

<figure>
<img src="/images/Hundter10.jpg">
</figure>

The main functionality of this method is contained almost entirely within this loop.

<figure>
<img src="/images/Hundter11.jpg">
</figure>

In short, the malware will take a low quality screenshot and send it over the socket at each iteration, then the screenshot will pause for 180 milliseconds.  If there are 50 (more) socket exceptions that are caught, the streaming will be set to false and stopped.  The DESKTOP_STREAM_DISABLE argument will also set the keepStreaming variable to false and stop the stream.

### Infrastructure

Passive information on the IP 78.46.74.130 shows several resolutions going back to mid-2015 and has the following domains.

<figure>
<img src="/images/Hundter12.jpg">
</figure>

Based upon the build strings of the binary
```
C:\Users\Hundter\Documents\Visual Studio 2015\Projects\NewRat\obj\x64\Debug\kstat.pdb
```

And the hardcoded file in the migrate section of the keylogger

<figure>
<img src="/images/Hundter13.jpg">
</figure>

It would be presumable to believe that hundter[.]com belongs to the malware author.  Which according to whois information is located in DK.

<figure>
<img src="/images/Hundter14.jpg">
</figure>

On the main page of hundter[.]com there is an advertisement for plex movies, downloads, “Admin Controls”, and a game server. 

<figure>
<img src="/images/Hundter15.jpg">
</figure>


At the copyright page in the source it also points to the names Lukas Hundt and Anton Due.  Which would be consistent to the email address.

<figure>
<img src="/images/Hundter16.jpg">
</figure>

### Conclusions

This keylogger has not been observed in the wild, and because of its debugging output, hardcoded paths, and lack of configuration files this leads us to believe that this is simply just a testing program to eventually build a fully fledged keylogger.

While the keylogger itself is very basic, it does have some support for more advanced functions like migrating processes.   Which can be effective when hiding and staying persistent on a box.  While this is just a tool in its infant stages, it’s worthwhile to study and check your defenses against these newly emerging utilities.

More builds of this binary (showing evolving various features over time) are below.

```
7156e5378b06eb829ebb0de191f0c3badcbb7d5095d9473ba6b8d9affba981fd
1396ea3ac0402cd68963ebe8d8c75ffd8cb1c05a3d1f7bda3c996dffc396fe00
509bff2d0714ae1d7206cf82af5c423020a08aa12f4eac893f12145eb0756600
65bbdf363ff0bb4670f958aa3d4ba3ea3cbf379f4c76a0c5060de76d21028c09
9ae357e1a92403a337665948a13b85524e2cc58d828bf8b7f006d9daa3bc801f
a2afe10a5b7a169ce6143c43537b236825429e0fca198a7a24bd108c7185c4df
```



