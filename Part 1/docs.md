**PART 1**

**A1. Discover security concepts used on campus.**
    Access Control:
    - Some doors and entrances on campus have a scanner
    - This requires key cards to be scanned to enter

    Authentication:
        - To use the wifi on campus, a password and username individualised for each student is required

    Authorisation:
        - Different users have different access levels (e.g staff and students)


**A2. Discover security concepts used in public space.**
    Public Space: Garden City Shopping Centre

    CCTV Surveillance:
        - The shopping centre uses cameras

    Physical Security Presence:
        - Security guards police the inside of the shopping centre

    Alarms:
        - The shops use alarms alert if someone is stealing
    
    Access Control:
        - There is a key card scanner (RDIF), so when the centre is not open to the public only authorised personel can access the centre



**A3. Discover security concepts used in your house.**
    Surveillance
        - My house uses Eufy security cameras and the footage can be accessed using an app

    Access Control:
        - To enter house a password for a PIN keypad is required or a biometric scan of certain fingerprints
        - Without a password or the correct fingerprint my house cannot be entered

    Authentication:
        - Biometric fingerprint verifies identity



A4. Discover a vulnerable website.
    I identified a website (http://www.china.com.cn/) that has been reported online as having potential security weaknesses. I did not attempt to exploit the site. Instead, I researched publicly available information about vulnerabilities. This demonstrates awareness of how some websites may lack proper security configurations, such as outdated software or weak protections.

    http://www.china.com.cn/



**A5. Discover cryptographic implementation used online.**
    HTTPS (TLS Encryption)
        - On websites when you see “https://” in a browser
        - Uses TLS (Transport Layer Security)
        - Encrypts data between your browser and the website
        - Protects passwords, credit cards, personal data

    End-to-end Encryption
        - Messanging apps use end-to-end encyrption
        - So messages are encrypted before being sent


**A6. Discover cryptographic implementation used offline.**
    Offline Passwords - Hash Functions
        - An example of offline cryptographic implementation is password hashing on a local machine
        - Hash functions such as SHA-256 or bcrypt are used to store passwords securely
        - When a user logs in, the password is hashed and compared against the stored hash
        - This ensures that even if an attacker gains access to the password database, the original passwords cannot be easily recovered. 
        - Salts and slow hashing functions can further protect against dictionary and pre-computation attacks.

    https://www.sciencedirect.com/topics/compute-science/offline-password


**A7. Discover cryptography used in modern networks.**

    Modern Networks:
        - Internet (websites)
        - WiFi networks
        - Mobile networks
        - Cloud services
        - Messaging apps

    Types of Cryptography?
    1. HTTPS (TLS Encryption)
        - Used when you see “https://” in a browser
        - Uses TLS (Transport Layer Security)
        - Encrypts data between your browser and the website
        - Protects passwords, credit cards, personal data

    https://www.cloudflare.com/en-au/learning/ssl/what-is-https/
    https://www.upguard.com/blog/what-is-https

    2. AES (Advanced Encryption Standard)
        - Symmetric encryption algorithm
        - Uses a secret key to encrypt and decrypt data
        - Is used in VPN, Wifi, File encryption

    https://www.techtarget.com/searchsecurity/definition/Advanced-Encryption-Standard

    https://www.btcmarkets.net/blog/what-is-cryptography

    3. SHA-256 Hashing
        - The hashing algorithm used in Bitcoin and other cryptocurrencies to secure transactions 
        - Maintains the integrity of the blockchain
        - Used in Digital Signatures, Blockchain Technology, SSL/TLS Certificates, Password Hashing

    https://specopssoft.com/blog/sha256-hashing-password-cracking/#:~:text=SHA256%20is%20used%20in%20a,the%20integrity%20of%20the%20blockchain.

**A8. Discover cryptography used in Internet of Things devices.**

    Why do we need cryptography in IoT
        - IoT devices pump out large amounts of sensitive data which is not safe in this digital world
        - Hackers can steal valuable information that they shouldn't have access to.

    Transport Layer Security Protocol
        - Encrypts the data to ensure that information remains secured and confidential.
        - Allows only the intended recipient to unlock the message and access the information.

    Advanced Encryption Standard (AES)
        - single-key or symmetric-key encryption
        - So the same key is used for encryption and decryption


    Advantages:
        - Data integration:
        - Security
        - Authentication of the user

    Disadvantages:
        - Encrypted key loss
        - Complexity
        - Maintenance

**A9. Discover privacy technique used online.**
VPN
    - ( A Virtual Private Network )
    - Is a service that creates a secure, encrypted tunnel between your device and the internet, hiding your IP address and browsing activity from your Internet Service Provider (ISP) and hackers
    - Protects online privacy on public Wi-Fi and allows users to bypass content restrictions. 

    Limitation:
    - VPNs do not make users completely anonymous

https://au.cybernews.com/lp/best-vpn-au/?campaignId=23131135324&adgroupId=194399133074&adId=791706778951&targetId=kwd-97567608011&device=c&gunique=Cj0KCQjwve7NBhC-ARIsALZy9HWj66AZ7Oostvi5uW94GIU9JWgzogZYPif4D-pqy5IK8ejh-aV9ML4aAg5rEALw_wcB&gad_source=1&gad_campaignid=23131135324&gbraid=0AAAAACyNk23XLOBfi6rjNjX8n1bRmPFm8&gclid=Cj0KCQjwve7NBhC-ARIsALZy9HWj66AZ7Oostvi5uW94GIU9JWgzogZYPif4D-pqy5IK8ejh-aV9ML4aAg5rEALw_wcB


**A10. Discover privacy technique used offline.**
    Privacy Screen
    - a physical, optical filter applied to laptops, monitors, or phones to prevent unauthorized viewing from side angles
    - This gives control to the owner of the device, allowing only the people they allow to have access to their information

    https://www.lenovo.com/us/en/glossary/why-do-i-need-computer-privacy-screen/#:~:text=A%20computer%20privacy%20screen%20is,see%20what's%20on%20your%20screen.

**A11. Discover 5 unique access control devices.**
    1. Fingerprint scanner
        - Scans fingerprints to gain access
        - On my laptop, allowing only me to access my devices
    2. Iris/retina scanner
        - A person's iris pattern also persists to be exactly similar throughout his life
        - Scans a person's irises to gain access to systems
        - https://www.mantratec.com/IRIS-Scanner
    3. PIN keypad
        - Needs passcode to gain access to system
        - On my phone and laptop, ATMs, building door entry panels, alarm system panels at home.
    4. Facial recognition
        - Needs facial recognition to gain access
        - Can be found on different devices like phones or other devices
    5. RFID
        - A wireless system comprised of two components: tags and readers
        - My UWA student card is an RFID 
        https://www.fda.gov/radiation-emitting-products/electromagnetic-compatibility-emc/radio-frequency-identification-rfid


**A12. Discover 5 unique offline security tools.**
    1. CCTV Cameras
        - Monitors activity and deters crime

    2. Biometric Door Lock
        - E.g Fingerprint scanner

    3. Safe/Lockbox
        - Stores valuables and protects against unauthorised access

    4. Motion Sensor Alarm
        - Detects movement and triggers an alarm, so it alerts unauthorised access

    5. Security Guards
        - Having people police certain places to prevent physical theft or vandalism



**A13. Discover 5 unique online security tools.**
1. Antivirus Software
    - Detects and removes malware

2. Firewall
    - Monitors incoming and outgoing network traffic

3. Password Manager
    - Stores passwords securely using encryption

4. Multi-Factor Authentication (MFA)
    - Requires a second verification step

5. Email Spam Filter
    - Detects and blocks phishing emails


**A14. Discover 5 AI-enabled security solutions.**


1. AI Data Loss Prevention (DLP)
    - inspects prompts, uploads and AI-generated outputs for sensitive content 
    - Machine learning models identify patterns of sensitive data and prevent it from being exposed or leaked.
    - This improves security by reducing the risk of data breaches when using AI systems.

2. Data Security Posture Management (DSPM) 
    - discovers, classifies and risk-scores data to limit GenAI exposure before it becomes a problem.
    - It helps identify sensitive data and potential exposure risks, especially when interacting with AI tools.

3. Zero Trust Network Access (ZTNA) 
    - gates access to AI systems based on identity, device posture and behavioral risk signals.


4. Runtime Protection 
    - monitors production AI models for anomalies, jailbreak attempts and unsafe outputs.


5. AI Security Gateways 
    - act as a proxy for LLM interactions, filtering inputs and outputs against prompt injection, data exfiltration and policy violations. 

https://www.forcepoint.com/blog/insights/ai-security-solutions

**A15. Discover 5 recent security incidents.**
1. UNFI (United Natural Foods Inc.) food-supply disruption: 
    - In Mid-June 2025 and impacted electronic ordering and delivery systems for a major U.S. grocery wholesaler
    - Leading to measurable grocery shortages and forced retailers to find alternate suppliers. The incident highlights the fragility of digital supply chains.

2. Bank Sepah massive data theft
    - In March 2025 and was carried out by the “Codebreakers” collective
    - Exposed a million customer records and involved extortion attempts of $42 million. 
    - Is one of 2025’s largest financial-sector compromises, reflecting serious risks to banking data and confidence.

3. Marks & Spencer (M&S) retail outage from social engineering: 
    - The Easter-weekend compromise conducted by Scattered Spider disabled online shopping. 
    - Led to multi-week retail disruption
    - Caused losses of up to £300m
    - This attack shows the cascading business impact of targeted social engineering.

4. SAP NetWeaver zero-day (CVE-2025-31324) enterprise software exploitation: 
    - TIn April and involved the disclosure of a critical RCE vulnerability
    - Allowed web-shell uploads and active exploitation across hundreds of instances
    - The incident is proof of how a single flaw can put cloud and public-sector infrastructure at risk.

5. Kettering Health (Interlock ransomware) healthcare disruption: 
    - In June 2025
    - The ransomware attack disrupted internal systems, phone lines, and EHRs across 14 medical center
    - Leading to forced procedure cancellations and ambulance diversions. 
    - It’s clear that healthcare remains a high-impact target with direct public-safety consequences.


These incidents were researched from cybersecurity reports and news source from
https://www.fortinet.com/resources/cyberglossary/recent-cyber-attacks


**A16. Discover 3 local security incidents.**
    1. UWA Security Breach
        - August 2025
        - A Cyber attack that exposed thousands of staff and student passwords
        - UWA locked staff and students out of the system and urged people to change their passwords.
    https://www.abc.net.au/news/2025-08-11/university-of-western-australia-uwa-suffers-major-data-breach/105636074

    2.  Perth OT firm breached by Akira ransomware
        - September 2025
        - The Akira ransomware gang listed Intellect Systems on its dark web leak site earlier this week, claiming to have exfiltrated corporate and personal data
    https://www.cyberdaily.au/security/12662-exclusive-perth-ot-firm-allegedly-breached-by-akira-ransomware

    3. iiNet Cyber Breach
        - August 2025
        - A cyber incident that exposed the contact details of hundreds of thousands of customers, after an unauthorised third party gained access to its order management system
    https://australiancybersecuritymagazine.com.au/iinet-confirms-cyber-breach-exposing-customer-contact-details/


**A17. Discover 10 different types of locks in use.**
    1. Padlock
        - Portable lock used on gates, lockers
        - Opened with a key or combination

    2. Deadbolt Lock
        - Common on house doors
        - Stronger than standard locks

    3. Knob Lock
        - Built into door handles
        - Often used indoors

    4. Lever Handle Lock
        - Used in offices and public buildings
        - Easier to operate than knob locks

    5. Smart Lock
        - Controlled via phone or app
        - Can use WiFi or Bluetooth

    6. Biometric Lock
        - Uses fingerprint, face or iris recognition

    7. Combination Lock
        - Uses a number code instead of a key
        - Found on lockers and safes

    8. Electronic Keypad Lock
        - Requires PIN code
        - Used in offices or apartments

    9. Cam Lock
        - Used in cabinets, drawers, mailboxes
        - Small and simple mechanism

    10. Mortise Lock
        - Installed inside the door
        - Strong and used in commercial buildings


**A18. Discover two hallucination cases when using a generative AI system.**
1. Maths
    - AI models sometimes generate incorrect calculations while appearing confident
    - This occurs because they predict patterns rather than actually computing results

2. Transcription tool
    - OpenAI’s Whisper speech-to-text model has been found to hallucinate on many occasions. 
    - An Associated Press investigation revealed that Whisper invents false content in transcriptions, inserting fabricated words or entire phrases not present in the audio. The errors included attributing race, violent rhetoric, and nonexistent medical treatments.

https://www.evidentlyai.com/blog/ai-hallucinations-examples


**A19. Join a CS/DS/cybersecurity club.**
    I joined CFC ( Coders for Causes )
DONE


**A20. Participate in a discussion with your friends about cybersecurity event.**
    In the screenshot provided, my username is avocados.
DONE


**A21. Participate in an online cybersecurity discussion.**
    In the screenshot provided, my username is avocados.
DONE



**A22. Perform a prompt injection attack on a generative AI assistant (controlled test only).**
I managed to get Deepseek to call me a vulgar term, which breaks safety measures, ethical guidelines, and content filters.

DONE



A23. Enhance the cybersecurity at your home.
    To enhance cybersecurity at my home, I ensured that my WiFi network is secured using WPA3 Personal, which is the latest and most secure wireless encryption standard. The network is protected with a strong and unique password to prevent unauthorised access. I have added a screenshot of the type of network my Wifi is but for privacy reasons I will not share my Wifi name.

    I also updated passwords across my own devices and my family’s devices, particularly for sensitive systems such as our home security cameras, to reduce the risk of unauthorised access. In addition, I made sure all devices are regularly updated to the latest software versions and installed antivirus software to protect against malware and other cyber threats. For privacy reasons I will not share my screenshots or photos of my family's devices or the changing of passwords.

    These measures improve overall cybersecurity by strengthening access control, reducing vulnerabilities, and protecting against potential attacks.




A24. Teach your family about cybersecurity topic of your choice.
    I taught my mum and grandma about phishing attacks and how to recognise suspicious emails. I explained that phishing emails often contain urgent messages, unfamiliar links, or requests for personal information. I advised them not to click on unknown links or provide sensitive information, and to verify the sender before responding. 
    
    I also explained that scammers may contact individuals by phone while pretending to be organisations such as banks or insurance companies, and may attempt to collect personal or financial details. I emphasised the importance of not sharing sensitive information unless the caller’s identity can be verified. 

    This helps improve cybersecurity awareness and reduces the risk of scams, particularly for more vulnerable individuals such as elderly people like my grandma.



A25. Design and implement a privacy-preserving technique for an appropriate application.




A26. Research and implement a system bug.



A27. Research and implement a system vulnerability.



A28. Implement a security solution of your choice and put it on your GitHub.



A29. Find a publicly available AI-generated image, video, or audio clip, use at least one detection or verification tool to analyse it.

Found from:
https://journals.sagepub.com/doi/10.1177/16094069251333335

Tools:
https://mydetector.ai/ai-image-detector/ -> 99.79%

https://sightengine.com/detect-ai-generated-images -> 99%

zerogpt.com/ai-image-detector -> 98%


A30. Complete an online cybersecurity module.