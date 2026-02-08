# Pikaptcha Sherlock | Hack The Box Walkthrough
> ## Using Wireshark and Registry Explorer to Investigate a Fake CAPTCHA Attack

### [>>GOOGLE DOC VERSION <<](https://docs.google.com/document/d/1wwwpNTuV9kx_fI00CCQKum2QC4FCfQF7w_YH9NAJTd0/edit?usp=sharing) (Originally posted on Medium.com)

*Completed 11/23/2025* -- *Jack Dignam*

- - - 
<p align="center"> <img width="320" height="320" alt="1_OeIUpWK-4IYDV5lnZG6a7w" src="https://github.com/user-attachments/assets/50daca96-ed64-468e-b952-096729bb514e" />
<p align="center"> https://app.hackthebox.com/sherlocks/Pikaptcha

# Introduction
My fourth ever [Hack The Box](https://www.hackthebox.com/) walkthrough is [Pikaptcha](https://app.hackthebox.com/sherlocks/Pikaptcha)! 
This lab is the 11th challenge of the **Intro to Blue Team** track that focuses on utilizing Wireshark to analyze captured network traffic and Registry Explorer to analyze the registry and attack payloads.

---

# Challenge Scenario
> Happy Grunwald contacted the sysadmin, Alonzo, because of issues he had downloading the latest version of Microsoft Office.
> He had received an email saying he needed to update, and clicked the link to do it.
> He reported that he visited the website and solved a captcha, but no office download page came back.
> Alonzo, who himself was bombarded with phishing attacks last year and was now aware of attacker tactics, immediately notified the security team to isolate the machine as he suspected an attack.
> You are provided with network traffic and endpoint artifacts to answer questions about what happened.

This challenge positions us as Alonzo, a sysadmin, analyzing provided artifacts of a suspected cyberattack on a colleague named **Happy Grunwald**. 
We will need to analyze Grunwald's **NTUSER.DAT** registry file to discover how his computer was compromised and delve deeper into our investigation. 
We are also provided with his network traffic at the time of the attack to utilize together to uncover what had occurred and what is compromised.

This challenge introduces a very unique type of attack called a **Fake Captcha Attack**, in particular a "Click Fix" attack. 
These type of attacks display realistic CAPTCHA challenges, but instead trick users to make them solve them on the attacker's behalf. 
Typically, a fake website is created of a target site that a user interacts with that contains a realistic CAPTCHA, which a user solves. 
Once solved, an attacker can forward the solution to a real site and bot traffic or automated attacks can continue on the target site. Some common red flags of this type of attack includes:

- CAPTCHA appearing on pages that shouldn't need one
- Pages appear low-quality or suspicious
- CAPTCHA appears before any context is shown
- The page asks you to solve multiple CAPTCHAS in a row

To analyze the events that occurred relating to this attack, we will need to utilize **Wireshark** and Eric Zimmerman's **Registry Explorer** for analysis. 
You can utilize other tools such as NetworkMiner, RegRipper, or ngrep for this investigation but I will just use these two.

If you find this walkthrough helpful, please feel free to **drop a follow**. Thank you for your consideration, now let's do this investigation!

---

# Setup the Lab Environment:
As a good rule of thumb before any simulated investigation, it is best to use a **virtual machine (VM)**. 
This ensures the environment is completely isolated and safe. This lab requires a Windows-based virtual machine which can be installed by following this tutorial (Windows 10):

[![](https://github.com/user-attachments/assets/e9091b5f-0e05-4b4c-9272-0e1e7e0ab851)](https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS)

https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS

From your Windows virtual machine, download the Hack The Box file and unzip it using the password `HackTheBlue`. We are provided with a network capture file and registry artifacts. 
For the capture file, you can use either NetworkMiner or Wireshark, but for this walkthrough I chose [Wireshark](https://www.wireshark.org/download.html).

As for the Registry artifacts, I will use [Eric Zimmerman's Registry Explorer](https://ericzimmerman.github.io/#!index.md) which is an open-source GUI tool used to analyze the registry. 
The version I am using is ***Registry Explorer v2.0.0.0*** which requires the latest version of Microsoft Windows Desktop Runtime to be installed beforehand.

With everything setup and ready to go, we can begin!

---
# Walkthrough
## Task 1: It is crucial to understand any payloads executed on the system for initial access. Analyze the registry hive for the user Happy Grunwald. What is the full command that was run to download and execute the stager?
To conduct a thorough analysis of an attack, it is essential to understand the nature of how the payload was initially executed. 
Different execution methods may leave different registry artifacts and execution context can distinguish persistence from a one-time execution.

To start, open **Registry Explorer** and click `File > Load Hive` in the top left corner. From there, navigate to Happy Grunwald's NTUSER.DAT file located in the challenge file under `C:/Users/happy.grunwald`. Hold **SHIFT** when selecting the file to avoid any potential *"Dirty Hive"* warnings.

<img width="1000" height="542" alt="1_vgTh5tM81RVpYsdg2XaUqA" src="https://github.com/user-attachments/assets/1a112091-20d6-458b-80a1-cbdcc06fa2bf" />

Once you have ingested the NTUSER.DAT file, search for *RunMRU* using the search function in the top left.

<img width="518" height="285" alt="1_d41DN-DNMy6G8LaKkYICxw" src="https://github.com/user-attachments/assets/c0ec54cf-e302-4705-b69b-efc387eeb746" />

**RunMRU** reveals the *"Run Most Recently Used"* list which contains a record of commands a user typed into the Windows Run dialog (Win +R). This is helpful for our investigation as it will help us discover what suspicious payloads may have executed at the time of compromise.

At the top middle of the screen, switch from values to RunMRU and look under executables. You will notice a suspicious powershell command that attempts to download an external script called `office2024install.ps1`. This is an immediate red flag therefore the answer must be this.

<img width="1000" height="105" alt="1_1J08xg3FuITRl0YfxuHUOw" src="https://github.com/user-attachments/assets/b9875ee7-89e2-4be8-bacb-962eabba8614" />

<img width="1000" height="166" alt="1_1alBxPF4rnS6vfeOd0WqBw" src="https://github.com/user-attachments/assets/aae5296b-99a5-4a9f-bdb3-b3410dbfce6a" />

--- 

## Task 2: At what time in UTC did the malicious payload execute?
We can view the UTC time that the malicious payload executed under the "Opened On" column on the same screen as before. 
This timestamp will be crucial in building a timeline of events for this investigation.

<img width="747" height="148" alt="1_3CIjC3WJb5IgEPILewemKg" src="https://github.com/user-attachments/assets/1c95c9fc-c9a0-44c4-89c5-074e8e62b973" />

The suspicious PowerShell payload was opened on **2024–09–23 05:07:45**.

<img width="1000" height="153" alt="1_BWDGmJVCWrsagbDleWuruw" src="https://github.com/user-attachments/assets/10659312-974f-47c0-8fc3-b21028ebf069" />

--- 

## Task 3: The payload which was executed initially downloaded a PowerShell script and executed it in memory. What is the sha256 hash of the script?
In Question 1, we discovered that the suspicious PowerShell command attempts to download an external script called `office2024install.ps1`. 
Using Wireshark, we can download this file to analyze its SHA256 hash.

To do this, open the `pikaptcha.pcapng` Wireshark capture and filter for packets containing the .ps1 file.

<img width="856" height="174" alt="1_Zr5Dius0La075pD3IzDo4g" src="https://github.com/user-attachments/assets/b31b78d0-a4a6-446d-a564-f7c4de6fe83c" />

The output confirms that a single HTTP GET request was made for this file in Happy Grunwald's network history. 
We can use this to export the HTTP object by navigating to File in the top left, "Export Options" and then clicking on "HTTP objects". 
From here, search for `office2024install.ps1` and download.

<img width="295" height="481" alt="1_WA3SJhUswS0ja1IF7ldSfw" src="https://github.com/user-attachments/assets/005ed49b-0ac4-44d8-8f08-d5dfce6d43b9" />

<img width="657" height="130" alt="1_PCEuAJgwRYJnGtL5Gg7OSQ" src="https://github.com/user-attachments/assets/c955c073-8fc3-4d91-9e07-d67bd1596df3" />

To be safe, do not open the file. 
Instead, search online for a SHA256 analyzer such as [https://hash-file.online/](https://hash-file.online/) and upload the downloaded file to view the results:

<img width="865" height="942" alt="1_b1tuC1uiTNUI6ZU5X_A13w" src="https://github.com/user-attachments/assets/c79c1ac7-1a75-4184-aa0e-d84d7287a6a2" />

```
SHA256: 579284442094e1a44bea9cfb7d8d794c8977714f827c97bcb2822a97742914de
```

<img width="1000" height="144" alt="1_jQxzJRx6Hz0PT35xc4NqQQ" src="https://github.com/user-attachments/assets/f8d6b82d-b172-4735-be4c-5d48aa213832" />

---

## Task 4: To which port did the reverse shell connect?
Knowing which port a reverse shell connected to is important during an investigation as it reveals how the attacker communicated with the compromised system. 
It helps us reconstruct the attacker's actions.

In question 3, we saw that there was one packet that contained the `office2024install.ps1` file. 
If we return to that packet and follow its TCP stream we can see what it contained. We can do this by right clicking on it, hovering over "follow" and then clicking on TCP stream.

<img width="1000" height="253" alt="1_ORo5ILgFbXmGb1LtZmhebg" src="https://github.com/user-attachments/assets/a78d925b-84f0-4563-b47b-5650a2277e5f" />

From here, we see a **Base64 encoded PowerShell script**. Using [Base64Decode](https://www.base64decode.org/), we can see what it contains.

<img width="980" height="565" alt="1_E83rIkUyiWtqkq9iErQU7A" src="https://github.com/user-attachments/assets/add29a89-9b02-4388-b370-556921e4d804" />

In the output of the base64 decode, we can see that the reverse shell connected to 43.205.115.44:6969. 
The **6969** portion of the IPv4 address is the port that was utilized.

<img width="1000" height="145" alt="1_0OOo7zj1NyQ_PYunwdNmQw" src="https://github.com/user-attachments/assets/5333f4ab-9816-4970-abec-a8820c48dd65" />

--- 

## Task 5: For how many seconds was the reverse shell connection established between C2 and the victim's workstation?
In the previous question, we discovered the IPv4 address that the attacker utilized to establish a reverse shell connection. 
If we filter for this address in Wireshark, we can see when the TCP connection was established and when it was disconnected.

If we filter using `ip.addr == 43.205.115.44`, we can see all conversations that had occurred between the attacker and host.

<img width="1000" height="523" alt="1_9tipxPSMpev3s0exW6t90Q" src="https://github.com/user-attachments/assets/fd883478-65fb-4dfe-b398-460104708325" />

By default in Wireshark, TCP conversations being established using the three-way handshake (SYN, SYN-ACK, ACK) are colored grey. 
Looking at when this occurred, reveals the shell connection starts at `146.26` under the time column.

If we scroll down until we see the next few dark grey packets, we can see the termination of the shell connection. 
In TCP conversations, this uses an alternating four-way handshake between FIN and ACK.

<img width="1000" height="529" alt="1_6ZXBuHaTMsotH20pdXzZEQ" src="https://github.com/user-attachments/assets/568585ec-47e8-4fa9-bf5e-3cd22b7f6597" />

At the very bottom, you can see the next grey strip packet.
You can also see under the 'info' column that FIN and ACK are exchanged. Under Time, the conversation was terminated at `549.57`. 
Subtracting the starting time from the ending time reveals that the connection lasted **403 seconds** or approximately **6.7** minutes.

<img width="1000" height="142" alt="1_PDM0aCe9dRjoad_hUsovuw" src="https://github.com/user-attachments/assets/855af5a6-445c-420b-96a3-951a890c55fe" />

--- 

## Task 6: Attacker hosted a malicious Captcha to lure in users. What is the name of the function which contains the malicious payload to be pasted in victim's clipboard?
We can view the exact code the attacker used for the malicious CAPTCHA because all traffic involved used HTTP (port 80). 
HTTP is not secure and does not encrypt data, therefore everything will be plaintext or bare minimum base64 encoded.

If we filter for `ip.addr == 43.205.115.44` || http in Wireshark, we can find the packet that contains the HTML code containing the CAPTCHA.

<img width="251" height="119" alt="1_yggpt61_yOMYIobeMBew7w" src="https://github.com/user-attachments/assets/235ea9dc-f91e-4a05-9ed3-6e6c900c50d2" />

By narrowing the traffic down using the attacker's IP, HTTP data, and scouring for exchanges with Happy Grunwald's IP, I found a packet containing the data for the CAPTCHA's HTML code that would be hosted on the website Grunwald visited.

<img width="785" height="595" alt="1_CuSN8Y4_ZcPmM5Hv4gSE1A" src="https://github.com/user-attachments/assets/d27fd0f0-4f50-4423-9b60-636e4e0d89d8" />

In the HTTP stream, we can see that in the HTML code the title for the webpage would be "**reCAPTCHA Verification**". 
If we continue analyzing the code, we see functions with malicious parameters towards the bottom.

<img width="1000" height="631" alt="1_YlxHKdTIOp8td4nWXvBWBg" src="https://github.com/user-attachments/assets/d467d0ff-65a8-467f-a650-bc2f0a813350" />

This includes a function called `stageClipboard` that builds a **malicious PowerShell command** and copies it to the user's clipboard. 
This is a common trick in fake CAPTCHA malware sites. 
For example, they show a *"Copy this Verification Command"* message, and when the victim pastes the command into either PowerShell, CMD, or Windows Run dialog they unknowingly run malware.

<img width="1000" height="148" alt="1_SMoAqecP6aU6A02YQS0FyQ" src="https://github.com/user-attachments/assets/04fafe28-9a94-4d41-9b37-32535c23a34c" />

--- 
# Conclusion

<img width="871" height="789" alt="1__rkMDOA60OwtNTExLVKG3Q" src="https://github.com/user-attachments/assets/ccf68e67-5ea7-4bd7-8861-a3108c1051be" />

The **Pikaptcha Sherlock** challenge from *Hack The Box* blends a clever mix of network capture investigation and registry analysis, discovering the usage of a malicious CAPTCHA webpage. 
It showcases how easily users can be manipulated into compromising their own environments through seemingly harmless interactions. 
Everything on the internet can be utilized in a malicious manner.

By inspecting the registry files using Eric Zimmerman's *Registry Explorer*, we discovered that a PowerShell payload was executed in memory which downloaded a file called **`office2024install.ps1`**. 
Analyzing network captures using Wireshark revealed a reverse shell was connected for **403 seconds** under the IPv4 address of `43.205.115.44` on port **6969**.

We also discovered how the CAPTCHA actually worked, which used a social-engineering technique called **ClickFix**. 
This form of attack manipulates the user into putting trust into a webpage and having them execute malicious commands. 
This falls under the [MITRE ATT&CK](https://attack.mitre.org/) technique of [T1204.004 (User Execution: Malicious Link)](https://attack.mitre.org/techniques/T1204/004/) which states that an adversary would weaponize links and web elements (such as a CAPTCHA) to trigger an unintended behavior.

If you found this walkthrough helpful, please feel free to **drop a follow**. Thank you for you reading!

## References
**Hack The Box Challenge**: https://app.hackthebox.com/sherlocks/Pikaptcha

**Eric Zimmerman's Tools**: https://ericzimmerman.github.io/#!index.md

**Wireshark**: https://www.wireshark.org/

**MITRE ATT&CK User Execution Technique (T1204.004)**: https://attack.mitre.org/techniques/T1204/004/

**Hash-File Online**: https://hash-file.online/

Base64 Decode: https://www.base64decode.org/
