# JAVA4SHELL IMPACT ANALYSIS

CVE-2026-114938 | Heap buffer overflow in the HotSpot JVM's AVX-512 Base64 decoder on x86-64 | Oracle CVSS 3.1: 8.1 | Red Hat: Critical, 9.8 (preliminary) | Fixed in 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1

Data cut-off: 18 November 2026, 08:00 UTC. Things are moving fast: several Java vendors and Linux distributions had not shipped a fix at the cut-off, so check NVD, CISA KEV, EPSS and your Java vendor's or distro's advisory again before you act on anything here.

---

## EXECUTIVE SUMMARY

### The situation at a glance

- **What:** A heap buffer overflow in the AVX-512 Base64 decoder that HotSpot's C2 JIT compiler uses in place of the Java code in java.util.Base64 on x86-64, tracked as CVE-2026-114938 (CWE-787 per Red Hat, CWE-122 in CISA's entry). On certain malformed, padded input that is too short to be valid Base64, the decoder computes a wrong output length and writes past the end of the output array before Java rejects the input. The public OpenJDK pull request that describes it says "The stub stores past the logical output length before returning to Java, corrupting the heap." Oracle lists Oracle Java SE, Oracle GraalVM for JDK and Oracle GraalVM Enterprise Edition (component: Compiler) and calls it a "Difficult to exploit vulnerability" that an unauthenticated attacker with network access via multiple protocols can use to compromise the product. Oracle's note adds that it can only be exploited by supplying data to APIs in that component, such as through a web service, and not through untrusted Java Web Start applications or applets. Java4Shell is the public name Calif, the security firm that found it, gave the bug, and CISA, Tenable, Qualys, The Hacker News, watchTowr and others use it. Oracle, OpenJDK and the CVE record use no nickname. Oracle credits Albert Yang, and Quang Luong of Calif.io. Calif's own page credits Quang Luong for the research, write-up and exploits, and Jenish Rakholiya for exploit improvement. The fix is four lines in HotSpot's x86-64 stub generator that hand a padded tail shorter than one block back to Java.
- **Risk level:** CRITICAL for internet-facing Java services on an affected build that run on x86-64 servers with AVX-512 VBMI (Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids or Granite Rapids, AMD from Zen 4 on), with the JVM defaults left on, starting with identity and single sign-on servers, CI and artifact servers, and Jira and Confluence. HIGH for internal services on that hardware, and for Java programs on that hardware that open TLS connections to servers you don't control. Patch in the normal window on ARM64 and on x86-64 without VBMI, because workloads move between machine types. Standard Java 8, Java 11 and Java 17.0.0 to 17.0.5 are not affected by this CVE, but still need the November updates, which fix other flaws. The scores run from Oracle's CVSS 3.1 8.1 (high attack complexity, "Difficult to exploit") to Red Hat's preliminary 9.8 Critical, with Amazon Linux at 8.8 Important and Calif at 9.2 under CVSS 4.0. CISA's alert calls it critical.
- **Impact:** Oracle says a successful attack can result in takeover, and its vector rates confidentiality, integrity and availability all high. What you should expect depends on whose account you read. VulnCheck calls crashing an affected JVM "trivial" if you can find and reach a sink that uses the vulnerable Base64 decode logic. It adds that a single request usually will not crash a default-configured server, but "a simple burst of requests reliably brought the service down in our testing". Calif says the bug can leak contents from the Java heap, "which may hold PII, private keys, other secret keys, and tokens". Calif also says it achieved code execution in default configurations: before login in Keycloak, Atlassian Jira, Atlassian Confluence, JFrog Artifactory, Jenkins and PingFederate, and after login in Apache Kafka Broker, Apache Solr, Elasticsearch, Gerrit and Spinnaker, plus sample apps on Apache Struts and Spring Boot. Calif says "The lists are non-exhaustive" and "there is no universal exploit". Independent labs have reproduced crashes and a memory leak but not code execution. Amazon's description is narrower: "exploitation could result in a JVM crash for unauthenticated users or, in certain application environments, code execution by an authenticated low-privileged user." Calif also describes a client-side variant: "A Java program that opens a TLS connection to a malicious server can be compromised, even if it exposes no service of its own."
- **Status:** Fixed upstream and by Oracle. Oracle and OpenJDK coordinated the release at 21:00 UTC on 17 November 2026. Fixed builds are Oracle Java SE 17.0.21.1+4, 21.0.13.1+4, 25.0.5.1+4 and 27.0.1.1+4 (all released 17 November), the OpenJDK tags jdk-17.0.21.1+2, jdk-21.0.13.1+2, jdk-25.0.5.1+2 and jdk-27.0.1.1+4, Oracle's Java 8 Performance Pack 8u513-perf, Oracle GraalVM for JDK 17.0.21.1, 21.0.13.1 and 25.0.5.1, and GraalVM Enterprise Edition 21.3.20.1. The fix sat in the public Java 27 update repository from 14 October 2026, and the overflow and the fix approach had been public in an OpenJDK pull request since 9 September, about ten weeks before the release. Amazon Corretto, Amazon Linux, Azul Zulu, SAP SapMachine, Heroku, Arch Linux, Homebrew and the Paketo azul-zulu buildpack also have fixed builds. Not fixed at the cut-off: Eclipse Temurin and the Docker images built on it, Microsoft Build of OpenJDK, Red Hat, BellSoft Liberica, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux. IBM Semeru is contested: Red Hat's VEX file lists a Semeru package on RHEL 10 as known affected, while IBM has made no statement. No exploitation in the wild has been confirmed, and the CVE is not in CISA's Known Exploited Vulnerabilities catalog (KEV). A full exploit is available to VulnCheck's paying customers, Calif keeps its product chains private, and the public repositories that mention the CVE are unverified. A stopgap exists for Java 11 and later: start the JVM with -XX:-UseBASE64Intrinsics and restart it.
- **Who's safe:** JVMs on a fixed build that have restarted since the update. A fixed package on disk doesn't fix a JVM that is still running. Java 11, standard Java 8 and Java 17.0.0 to 17.0.5 are not affected by this CVE. Red Hat says "Customers running OpenJDK 8 or OpenJDK 11 are also not affected, as these versions do not contain the vulnerable code path." On the hardware side, ARM64 (AWS Graviton, Ampere), Intel Skylake-SP, Cascade Lake and Cooper Lake, Intel Xeon Sierra Forest and AMD Zen 3 and older are not exposed. A JVM is also not exposed when UseBASE64Intrinsics is false, when UseAVX is 2 or lower, or when only the C1 compiler runs (TieredStopAtLevel is 1). The MIME decoder skips the vector path. Google has masked AVX-512 VBMI for managed Java 17, 21 and 25 runtimes on App Engine standard and second generation Cloud Run through 30 November 2026, and the default settings of Azure Functions keep the path off. Neither is permanent: Google's masking ends on 30 November, and options that turn C2 back on bring the path back on Azure Functions.
- **Who's at risk:** Any JVM where all four conditions hold: an affected build, a VBMI CPU visible to the JVM, the Base64 intrinsic on with C2 running, and an application that passes attacker-supplied Base64 to the basic or URL-safe decoder. In practice that is the newest Java on the newest x86 hardware (our reading): Java 17.0.6 and later, 21, 25 and 27 on Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids and Granite Rapids, on AMD from Zen 4 on, and on cloud families such as AWS c6i, m6i, r6i, c7i and m7i, Azure Dsv5, Dsv6 and Dasv6, and Google Cloud C3 and C4. Products that carry their own Java stay at risk until their vendor ships an update, because updating the system Java doesn't change them: Jira, Confluence, Elasticsearch, Keycloak, Jenkins and others. Platforms with no fixed build are worst off: Eclipse Temurin and the images built on it, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux. Java programs on VBMI hardware that open TLS connections to servers you don't control are also at risk, even if they expose no service of their own.

*Sources: Oracle Critical Security Patch Update of November 2026, OpenJDK advisory of 17 November 2026, CVE record (including CISA's SSVC entry), Red Hat CVE page, bulletin RHSB-2026-018 and VEX file, Amazon Linux Security Center, Calif's write-up, the OpenJDK fix commit, Oracle release notes, vendor and distro pages and trackers (see Where the fix comes from), CISA alert and KEV feed, VulnCheck, The Hacker News*

### What this means for your organization

A JVM is exposed only when four conditions hold at once. It runs an affected HotSpot build. It runs on an x86-64 CPU with AVX-512 VBMI and BW visible to the JVM, with UseAVX at 3, which is the default on those CPUs. The Base64 intrinsic is on, which is the default, and the C2 compiler is running, which is the default for long-running servers. And the application passes attacker-supplied Base64 to the basic or URL-safe decoder. Red Hat names typical carriers: HTTP Basic credentials, SAML artifacts, CSRF tokens and MIME encoded words. Updating your own application code doesn't fix the bug. A fixed Java runtime and a restart do.

The hardware condition turns the usual rule around. The newest Java on the newest x86 hardware is exposed, and teams still on older Intel chips or on ARM are clear by accident (our reading). A version number can't tell you which side of that line a host is on, because version banners say nothing about the CPU. The table under Where the exposed hardware is lists the processors and cloud families.

Which Java a product runs matters as much as which version your servers have. Many products carry their own, and patching the system Java doesn't change a bundled one:

- Bundled runtimes. The Jira and Confluence installers bundle Eclipse Temurin. Elasticsearch runs its bundled JDK by default, and its development branch pins bundled JDK 27.0.1.0.3, an affected build.
- Official container images. The official Jenkins image carries a Temurin runtime and gets the fix only after Adoptium publishes and Jenkins rebuilds. Keycloak's image uses the UBI 9 java-21-openjdk-headless package, so its fix follows Red Hat's errata. The official Tomcat and Kafka images are built on eclipse-temurin.
- Java you install yourself. PingFederate's zip install, and Tomcat and Kafka tarball installs, use the system Java or one you provide.
- JFrog Artifactory: we couldn't verify where its Java comes from, because its documentation was unreachable.

CISA's advice is to review your software inventory for JDKs and Java runtimes, including those bundled with third party applications or included in container images and appliances, and it warns that they may not appear as separate entries in software inventories. The table under Products that carry their own Java has the detail.

The CPU belongs to the machine, not to the image, so the same container image can be exposed on one node and safe on the next. HotSpot turns AVX-512 on only when the CPU reports it and the operating system has enabled its register state, so a hypervisor that masks VBMI removes the path. Run the CPU check inside each guest, and treat any node pool that contains a VBMI node as exposed (our reading). Red Hat's bulletin names as "most likely" affected "AWS C6i/M6i/R6i and C7i/M7i/R7a, GCP C3/C3D/C4/C4D/N4/N4D/M3/M4, and Azure Dsv5/Dsv6/Dasv6/Dasv7", plus related D-series v5 to v7 SKUs. The table under Where the exposed hardware is also lists the families that are clear, such as AWS c5 and m5, Graviton, and Google Cloud N2D. Container images need a second look too: the Amazon Corretto images were rebuilt under their old tag names, so a tag name doesn't prove a fixed image.

Managed platforms differ:

- Google: "As an interim platform safeguard through November 30, 2026, Google has masked AVX-512 VBMI for managed Java 17, 21, and 25 runtimes on the App Engine standard environment and the Cloud Run second generation execution environment (including 2nd gen Cloud Run functions)". It "does not cover the Cloud Run first generation execution environment, Cloud Functions (1st gen), App Engine flexible environment, Cloud Run jobs and worker pools, custom containers, or deployments without automatic base image updates".
- Heroku moved its defaults to 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, effective 18 November.
- Azure Functions: the Java worker starts the JVM with -XX:+TieredCompilation -XX:TieredStopAtLevel=1, so only C1 runs and the default configuration doesn't reach the stub. Options that re-enable C2 (for example -XX:TieredStopAtLevel=4 or -XX:-TieredCompilation in JAVA_OPTS, languageWorkers__java__arguments or _JAVA_OPTIONS) bring it back. The Azure issue checked whether the intrinsic was used. It did not test memory corruption. Microsoft has published no advisory.
- AWS Lambda, Elastic Beanstalk and Azure App Service: we found no statement.

Three things no source settles yet. First, whether decode(ByteBuffer) or wrap(InputStream) reach the stub. Second, how much work it takes before C2 compiles the decode path. Third, how the client-side path works. Don't read the gaps as safety.

If an attacker gets this working against one of your JVMs, they can:

- Crash it. This is the likeliest harm this week (our reading). VulnCheck's testing brought a default-configured service down with a burst of requests, and Blackpoint, per The Hacker News, crashed a test Spring Boot application.
- Read the Java heap, which may hold PII, private keys, other secret keys and tokens (Calif's words). The read can leave no crash (our reading), so a clean crash log doesn't clear a JVM.
- Run code, in the products Calif lists. That is Calif's claim. Independent labs haven't reproduced it, and it needs work tailored to each product (our reading).
- Compromise a Java program that opens a TLS connection to a malicious server, even if the program exposes no service. No source says how that path works.

No indicators of compromise have been published beyond scanner traffic, so there is little to match against yet.

Real-world context: The overflow and the fix approach were public from 9 September 2026, when an OpenJDK pull request described them, about ten weeks before the release. The fix reached the Java 27 update repository on 14 October under the bland title "8393212: Base64 optimization improvements", and the Java 17, 21 and 25 update repositories on 12 November. Oracle reserved the CVE number on 22 October. Word got out before the release. On 17 November the Korea Times reported at 14:26 UTC that South Korea's National Intelligence Service had told public institutions to prepare for a critical Java flaw, and at about 16:11 UTC Calif posted on X that details had leaked and that it would publish after Oracle's patch. The OpenJDK advisory and Oracle's Critical Security Patch Update came out together at 21:00 UTC, the CVE record followed at 21:32 UTC, and NVD received it at 22:18 UTC. No exploitation in the wild has been confirmed. The CVE is not in CISA KEV (catalog 2026.11.17), and CISA's SSVC entry says Exploitation none. The Canadian Centre for Cyber Security says it "is not aware of active exploitation at this time, but that can change quickly", VulnCheck says it is "not known to be exploited in the wild at time of writing", and Tenable, Qualys and Horizon3 report none. No source names a threat actor, campaign or malware. GreyNoise has tagged Java4Shell traffic since 01:18 UTC on 18 November, and at 07:18 UTC its tracker showed 3 IPs, 53 requests and 0 successful intrusions. There is no EPSS score yet.

Exploit code is where the sources part ways. Calif keeps its product chains private: "The weaponized chains for individual products stay private until everyone has had a chance to upgrade. We will publish them later." VulnCheck says "A full RCE exploit for CVE-2026-114938 is available to Initial Access Intelligence customers as of 6 PM EST on November 17" (23:00 UTC), shipped "with a version scanner, a PCAP, and Snort, Suricata, Sigma, and YARA rules." Tenable relays that Immersive said on X it had developed a working exploit that "has to be adapted to each application", and the post does not say it was released. Independent labs have reproduced crashes and a memory leak but not code execution. Upwind reproduced the overflow on an AWS c6i instance (Intel Ice Lake) and crashed the JVM. Blackpoint, per The Hacker News, ran a memory-read test that "worked in all 30 runs" and "did not reproduce remote code execution". Pentestit says "Code execution is still only Calif's claim", and Equixly says "Denial of service is the realistic impact." VulnCheck doesn't expect the bug to be easily or widely exploitable, but expects adversaries to find narrow but functional paths to code execution in specific applications. watchTowr says it rated the CVE highly likely to be exploited in the wild when it was disclosed. Upwind lists the idea that it is only a crash as a wrong claim, because Calif demonstrated heap disclosure and code execution. There is no Metasploit module, and a Nuclei template that checks versions is proposed but not merged.

A GitHub search at 07:46 UTC on 18 November found 25 repositories that mention the CVE. By their descriptions, 12 are tools, scanners, detection or mitigation projects, 5 are labs or local reproductions, 2 claim exploits, 2 are write-ups and 4 are empty. None is verified, and we name none. Pentestit's advice applies: "Read any script before you run it." Government agencies have published notices: CISA (alert of 17 November), the Canadian Centre for Cyber Security (AL26-029, 20:27 UTC on 17 November), NCSC-NL (NCSC-2026-0495, 21:55 UTC on 17 November) and Switzerland's BACS (warning of 18 November, 06:33 to 06:41 UTC). South Korea's intelligence service rated it critical before disclosure, its science ministry and KISA advise urgent inspection and updates, and its presidential office held an emergency meeting on 17 November. Nobody has published an internet-wide count of exposed systems.

*Sources: Oracle Critical Security Patch Update, OpenJDK advisory, CVE record and CISA SSVC data, NVD, FIRST EPSS API, CISA alert and KEV feed, Red Hat bulletin RHSB-2026-018, Calif's write-up, VulnCheck, Upwind, The Hacker News, Tenable, Qualys, Horizon3, Pentestit, Equixly, watchTowr, GreyNoise tracker, Korea Times, Canadian Centre for Cyber Security, NCSC-NL, Switzerland's BACS, Google Cloud support bulletins, Heroku changelog, Azure Functions Java worker issue and documentation, Atlassian, Jenkins, Keycloak, Elastic, Ping Identity, Apache Tomcat and Kafka documentation and image files, AWS, Azure and Google Cloud documentation, GitHub repository search*

### Immediate actions required

HOUR 1: Find every JVM, bundled ones included, and the hardware under it

1. List the servers, containers, VM images and products that run Java. Include the images you build yourself, golden images, VM templates and autoscaling launch configurations, so new instances don't start on an old runtime, and the products that carry their own Java (Jira, Confluence, Elasticsearch, Keycloak, Jenkins and others). CISA warns that JDKs and Java runtimes may not appear as separate entries in a software inventory.
2. Get the live version and flags of each JVM: `jcmd -l` lists the JVMs on a host, `jcmd <pid> VM.version` gives the live version, and `jcmd <pid> VM.flags -all` shows whether the vulnerable path is on (run them as the JVM's user or root). JVMs inside containers don't show on the host, so run the checks inside each container. Judge each build by its own vendor's list: the October respins ending in .0.3 look newer than the October releases but are the last vulnerable builds. The Quick status check in the RISK DASHBOARD has the commands.
3. Mark the JVMs where all four conditions hold. Internet-facing ones come first, starting with identity and single sign-on servers, CI and artifact servers, and Jira and Confluence. In a virtual machine or a Kubernetes node pool, run the CPU check inside each guest, because the same image can be exposed on one node and safe on the next.
4. Check your managed platforms. Google's masking, Heroku's new defaults and the Azure Functions defaults change the answer, and AWS Lambda, Elastic Beanstalk and Azure App Service have no statement.

DAY 1: Patch or apply the stopgap, then restart

1. Install the fixed build for your vendor (see Where the fix comes from) and restart every JVM that used the old runtime. Patch internet-facing identity and single sign-on servers, CI and artifact servers, and Jira and Confluence on VBMI hardware first, then other services on that hardware, then everything else in the normal window, because workloads move between machine types. Java 8 and 11 hosts still need the November updates, which fix other flaws. Products with their own Java need the product vendor's update or a supported swap of the runtime. Updating the system Java does not change them. Retired lines (18 to 20, 22 to 24 and 26) get no fix: move them to 21.0.13.1, 25.0.5.1 or 27.0.1.1. For Docker, rebuild your image on a fixed base and redeploy, then check the version inside the image, because the Amazon Corretto images kept their old tag names. Retire golden images, VM templates and autoscaling launch configurations that still carry an affected runtime. The commands for each platform are under IMMEDIATE ACTIONS in the PROTECTION ROADMAP.
2. If you suspect a JVM, save its logs, any hs_err crash logs and a list of running processes before you restart it, because a restart replaces the running process. Treat dumps and crash logs as sensitive: a heap dump is full of secrets.
3. Confirm after the restart. A fixed package on disk doesn't fix a JVM that is still running, and a release file only describes the runtime on disk. Check the live process with `jcmd <pid> VM.version`.
4. If patching has to wait, apply the stopgap. Red Hat's preferred option is to start each affected JVM with -XX:-UseBASE64Intrinsics, which "disables the hardware-accelerated Base64 implementation only", then restart it. Calif recommends it too. The alternative, -XX:UseAVX=2, turns off all AVX-512 code in the JVM and works on x86-64 only. The Canadian Centre and Google recommend it. OpenJDK 8 doesn't know the first flag and would refuse to start, and no source says whether Oracle's Java 8 Performance Pack accepts it. Where the flag goes decides whether it works: JAVA_TOOL_OPTIONS is read by the JVM itself, JDK_JAVA_OPTIONS only by the java launcher, Elasticsearch strips both, and Keycloak's JAVA_OPTS replaces its defaults, so products need the flag in their own configuration (see Products that carry their own Java). Base64-heavy work such as tokens and SAML may slow down, and nobody has published numbers, so test one node first (our reading). Remove the flag once the fixed runtime is confirmed. Network controls are a layer, not a fix. The stopgap commands are under IMMEDIATE ACTIONS in the PROTECTION ROADMAP.

DAY 2: Look for compromise, then rotate secrets where it applies

1. Look for JVM crash logs (hs_err_pid<pid>.log, "A fatal error has been detected by the Java Runtime Environment"), container restart counts and unexplained service restarts since 9 September 2026. Endor Labs' signature is "Repeated hs_err crashes with a SIGSEGV in a garbage-collection copy routine and a compiled Base64$Decoder.decode0 frame, especially clustered by source", and no JDK vendor has confirmed it. Prophet Security says "Expect a failed attempt to look like a crashed JVM, or like an ordinary rejected request."
2. Look for malformed, padded Base64 in Authorization headers, cookies, SAML fields and tokens, and for bursts of IllegalArgumentException from java.util.Base64$Decoder on endpoints that need no login. Prophet adds that many frameworks catch the exception and reject the request without logging it, so a quiet application log does not rule out an attempt.
3. Look for Java processes that start shells or download tools, and for new outbound connections from Java processes. Build servers start shells legitimately.
4. Look for oversized or binary-looking responses from endpoints that echo decoded input. That is the only sign of the memory read (our reading).
5. Rotate secrets where it applies (our reading). Patching closes the hole but doesn't undo a memory read, and the memory read can leave no crash. First tier: if an internet-facing identity, single sign-on, CI or artifact server ran an affected build on VBMI hardware with the intrinsic on, and was neither patched nor flagged after 21:00 UTC on 17 November 2026 (the coordinated release, by Calif's account; a commercial exploit followed two hours later), rotate its signing keys and stored credentials after patching, and invalidate the sessions and tokens it issued. Second tier: for any other affected service, rotate the secrets it held if your logs show the warning signs above at any point since 9 September 2026. The list: database passwords, API keys, cloud credentials, OAuth and OIDC client secrets, JWT and SAML signing keys, TLS private keys in Java keystores, and secrets in configuration or the environment.

Semgrep's warning applies to every step: "A WAF rule, a lack of alerts or a lack of crashes does not prove that a runtime is patched or that no attempt occurred."

### Business impact assessment

Financial risk:

- No confirmed compromise has been reported, so there is no incident cost to quote for this bug.
- The fix itself is a runtime update and a restart. The costly cases are the ones with no fixed build yet and the products where a vendor controls the runtime. Eclipse Temurin, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux had no fixed build at the cut-off, and we found no statement about their products from Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache (Tomcat, Kafka, Solr), Cisco, IBM or SAP (see Where the fix comes from).
- Oracle's next Critical Security Patch Update is on 15 December 2026 and its next quarterly Critical Patch Update on 19 January 2027. Oracle's notes for 17.0.21.1 say it is not recommended to use that build after the January update.
- Finding every runtime is the hidden cost. Java sits inside products, container images, golden images and VM templates, and a base image can carry an old runtime into every new instance.

Operational risk:

- Every fix and every stopgap needs a restart of each JVM. Plan the windows.
- Crashes are the likeliest harm this week (our reading). A burst of requests can take a service down, and Prophet Security says to expect a failed attempt to look like a crashed JVM or an ordinary rejected request.
- Version scanners will be noisy and partly blind. A version scanner can't see the CPU or the JVM flags, and dependency scanners can't see the runtime, so a flagged host may be on ARM and safe while an unflagged one carries a bundled runtime. NVD has no product data for this CVE yet, so tools that read NVD alone miss it, and the Ubuntu, SUSE and Alpine feeds have no entry. Qualys (QID 389494) and Tenable (plugins 382091 and 382045) have checks, and Rapid7 has an authenticated one.
- The stopgap may slow Base64-heavy work such as tokens and SAML. Nobody has published numbers, so test one node first (our reading).
- Don't count on a WAF. AWS WAF's Known Bad Inputs rule group version 1.28 adds Java4Shell rules, but in Count mode, so they log and don't block until you change the action. Cloudflare's WAF changelog had no Java4Shell entry (newest item 12 November). Size limits alone won't stop it, because the malformed input that triggers it is short (our reading of Endor Labs' description of the trigger). No network control recovers data already read from memory.

Legal risk:

- If a compromised service held personal data, breach notification clocks start when you become aware of the breach. The deadlines by jurisdiction are in COMPLIANCE & LEGAL REQUIREMENTS. The memory read is the case to watch, because Calif says the heap "may hold PII", and our reading is that a memory read can leave no crash, so you may not know it happened.
- US federal agencies and PCI DSS have patch deadlines that hang off the rating. They are in COMPLIANCE & LEGAL REQUIREMENTS too.

*Sources: Oracle Critical Security Patch Update and release notes, CISA alert, Red Hat bulletin RHSB-2026-018, Calif's write-up, Canadian Centre for Cyber Security, Google Cloud support bulletins, Prophet Security, Endor Labs, Semgrep, Qualys, Tenable, Rapid7, AWS WAF and Cloudflare WAF changelogs, NVD, Ubuntu, SUSE and Alpine security feeds, vendor release pages and trackers (see Where the fix comes from)*

---

## RISK DASHBOARD

### Severity metrics

| Metric | Rating | What it means |
| --- | --- | --- |
| **Overall risk** | CRITICAL for internet-facing Java services on an affected build, on x86-64 with AVX-512 VBMI and the JVM defaults on. HIGH for internal services on that hardware, and for Java programs on it that open TLS connections to servers you don't control | Oracle scores it CVSS 3.1 8.1, Red Hat 9.8 Critical (preliminary), Amazon Linux 8.8 Important and Calif 9.2 under CVSS 4.0. CISA calls it critical. A score can't tell you whether your hosts have AVX-512 VBMI, so use the four conditions to decide where you are exposed. Patch in the normal window on ARM64 and on x86-64 without VBMI. Other sources are in the table below |
| **Attack complexity** | HIGH per Oracle, LOW per Red Hat and Amazon Linux | Oracle's vector is AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H and its wording is "Difficult to exploit". Red Hat's is the same except AC:L, under CVSS 3.0. Amazon Linux's is AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H. NCSC-NL says it is not easy to abuse because successful exploitation has several requirements. The split is explained under the second table |
| **Authentication needed** | NONE per Oracle and Red Hat (PR:N), LOW per Amazon Linux (PR:L) | Oracle describes an unauthenticated attacker with network access. Amazon describes a JVM crash for unauthenticated users and, in certain application environments, code execution by an authenticated low-privileged user. Calif claims code execution before login in six products and after login in five others |
| **User interaction** | NONE | UI:N in all three vectors. Nobody has to click anything |
| **Reach** | ONLY WHEN FOUR CONDITIONS HOLD AT ONCE | An affected build. An x86-64 CPU with AVX-512 VBMI and BW visible to the JVM, with UseAVX at 3. The Base64 intrinsic on with C2 running. Attacker-supplied Base64 passed to the basic or URL-safe decoder. The MIME decoder skips the vector path. Calif also describes a client-side variant where a Java program opens a TLS connection to a malicious server, and no source says how that path works |
| **Likely harm** | CRASH is the likeliest. MEMORY READ is possible. CODE EXECUTION is claimed by Calif and not reproduced by independent labs | VulnCheck calls a crash "trivial" if you can reach a sink, and a burst of requests reliably brought a default-configured service down in its testing. Calif says the heap read can expose secrets. Independent labs have reproduced crashes and a memory leak but not code execution. Our reading: the memory read can be quiet, and code execution needs work tailored to each product |
| **Patch available** | YES for Oracle, OpenJDK and several vendors. NO at the cut-off for Temurin, Red Hat, Debian, Ubuntu and others | Fixed builds came out on 17 November 2026 (Oracle Java SE 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1). Not fixed at the cut-off: Eclipse Temurin, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux. A stopgap flag works on Java 11 and later in the meantime (see the PROTECTION ROADMAP) |
| **Active exploitation** | NOT CONFIRMED IN THE WILD | CISA's SSVC entry says Exploitation none, the CVE is not in CISA KEV (catalog 2026.11.17), and Tenable, Qualys and Horizon3 report none. GreyNoise counted 3 IPs, 53 requests and 0 successful intrusions at 07:18 UTC on 18 November. A full exploit has been available to VulnCheck's paying customers since 23:00 UTC on 17 November |
| **EPSS** | NO SCORE YET | Reading at the cut-off |
| **NVD record** | RECEIVED, NO NVD SCORE | NVD received the record on 17 November 2026 at 22:18 UTC. It has no CPE data and no NVD score, and the page shows Oracle's 8.1 |

Ratings by source:

| Source | Rating | Note |
| --- | --- | --- |
| Oracle (CNA) | CVSS 3.1 8.1 | Vector AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H. Oracle's wording is "Difficult to exploit". Component: Compiler |
| Red Hat | Critical, CVSS 3.0 9.8 | Vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, "preliminary and subject to review", CWE-787. Bulletin RHSB-2026-018 has the status "Ongoing" |
| Amazon Linux | Important, CVSS 3.1 8.8 | Vector AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H. Its description differs from Oracle's: a JVM crash for unauthenticated users or, in certain application environments, code execution by an authenticated low-privileged user |
| Calif | CVSS 4.0 9.2 (Critical) | "Under CVSS 4.0, this vulnerability scores 9.2 out of 10 (CRITICAL)". No vector is published |
| CISA | Critical (alert wording) | The alert calls it "This critical memory-corruption vulnerability". SSVC entry in the CVE record: Exploitation none, Automatable no, Technical impact total, weakness CWE-122 |
| NVD | Status "Received" | No CPE data and no NVD score of its own. The page shows Oracle's 8.1 |
| Canadian Centre for Cyber Security | Critical | AL26-029, titled "Critical vulnerability impacting Oracle Java" |
| South Korea's National Intelligence Service | Critical | Per the Korea Times, before disclosure |
| Switzerland's BACS | Critical | Calls it a critical vulnerability in its warning of 18 November |
| NCSC-NL | Medium likelihood, high impact (M/H) | Advisory NCSC-2026-0495. It says the bug is not easy to abuse because successful exploitation has several requirements |
| EPSS | No score yet | Reading at the cut-off |
| CISA KEV | Not listed | Catalog 2026.11.17 |

The spread comes down to how each source reads the attacker. Oracle's 8.1 rests on high attack complexity. Red Hat's 9.8 uses low complexity under CVSS 3.0. Amazon's 8.8 assumes a logged-in attacker. Calif's 9.2 is a CVSS 4.0 score with no published vector. Our reading is that none of these numbers can tell you whether your own hosts have AVX-512 VBMI, which is why this analysis ranks by exposure and not by score.

My read: treat it as critical for internet-facing Java services on an affected build that run on x86-64 servers with AVX-512 VBMI (Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids or Granite Rapids, AMD from Zen 4 on), with the JVM defaults left on, starting with identity and single sign-on servers, CI and artifact servers, and Jira and Confluence. Treat it as high for internal services on that hardware, and for Java programs on that hardware that open TLS connections to servers you don't control. Patch in the normal window on ARM64 and on x86-64 without VBMI, because workloads move between machine types. Standard Java 8, Java 11 and Java 17.0.0 to 17.0.5 are not affected by this CVE, but still need the November updates, which fix other flaws. For critical: Red Hat scores it 9.8, Calif claims code execution before login in six products in their default configurations, a full exploit is available to VulnCheck's paying customers, no login is needed in Oracle's and Red Hat's vectors, and the overflow and the fix approach have been public since 9 September. Against that, Oracle rates attack complexity high and calls it "Difficult to exploit", NCSC-NL says it is not easy to abuse, CISA's SSVC entry says Exploitation none and Automatable no, the CVE is not in KEV, nobody has confirmed exploitation, and independent labs have reproduced crashes and a memory leak but not code execution. Crashes are the most likely harm this week, the memory read can be quiet, and code execution needs work tailored to each product (our reading). The signs that this has changed would be Calif's release of its product chains, a merged Nuclei template, a Metasploit module or a KEV listing. Internal services on that hardware stay at high, because the vectors need only network access and no login.

*Sources: Oracle Critical Security Patch Update, CVE record (Oracle's entry and CISA's SSVC data), NVD, Red Hat CVE page and bulletin RHSB-2026-018, Amazon Linux Security Center, Calif's write-up, CISA alert and KEV feed, FIRST EPSS API, Canadian Centre for Cyber Security AL26-029, NCSC-NL advisory NCSC-2026-0495, Switzerland's BACS warning, Korea Times, GreyNoise tracker, VulnCheck, Tenable, Qualys, Horizon3, The Hacker News*

### Affected versions: quick lookup

| Release line | Status on 18 November 2026 | Affected builds | Fixed in |
| --- | --- | --- | --- |
| Java 27 | Affected until updated | 27.0.1.0.3 and earlier builds | 27.0.1.1 (Oracle 27.0.1.1+4, OpenJDK jdk-27.0.1.1+4) |
| Java 25 | Affected until updated | 25.0.5.0.3 and earlier builds | 25.0.5.1 (Oracle 25.0.5.1+4, OpenJDK jdk-25.0.5.1+2) |
| Java 21 | Affected until updated | 21.0.13.0.3 and earlier builds | 21.0.13.1 (Oracle 21.0.13.1+4, OpenJDK jdk-21.0.13.1+2) |
| Java 17.0.6 and later | Affected until updated | 17.0.6 to 17.0.21.0.3 | 17.0.21.1 (Oracle 17.0.21.1+4, OpenJDK jdk-17.0.21.1+2) |
| Java 17.0.0 to 17.0.5 | Not affected by this CVE | None. 17.0.5 does not contain the AVX-512 decoder | n/a |
| Java 18 to 20, 22 to 24 and 26 (retired lines) | Affected, no fix | Every release | None. Move to 21.0.13.1, 25.0.5.1 or 27.0.1.1 |
| Oracle Java 8 Performance Pack | Affected until updated | 8u511b33-perf and earlier builds | 8u513-perf (1.8.0_513-perf-b4) |
| Standard Java 8 | Not affected by this CVE | None. Only the Performance Pack build has the code | n/a |
| Java 11 | Not affected by this CVE | None. Java 11 has no AVX-512 decode intrinsic (only an encode one), and the 2021 change was never backported | n/a |
| Oracle GraalVM for JDK | Affected until updated | 17.0.21.0.3 and 21.0.13.0.3 (Oracle's list), and earlier builds | 17.0.21.1, 21.0.13.1 and 25.0.5.1 |
| Oracle GraalVM Enterprise Edition | Affected until updated | 21.3.20.0.3 and earlier builds | 21.3.20.1 |
| GraalVM Native Image | Probably not affected (inferred) | Native executables don't run HotSpot's C2 compiler. No vendor has said so | n/a |
| IBM Semeru (OpenJ9) | Contested | Red Hat's VEX file lists java-21-ibm-semeru-certified-jdk on RHEL 10 as known affected. IBM has made no statement, and OpenJ9 issue 25216 is open with no reply | No statement |

Three version traps. First, the October respins ending in .0.2 and .0.3 (17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 and 27.0.1.0.3) look newer than the October releases but are the last vulnerable builds. The fix is the .1 build. Second, vendors number their builds differently. Corretto adds a fifth field (17.0.21.1.2), Azul Zulu has its own numbers (17.70.201), and some write-ups wrongly cite 17.0.11 and 21.0.3 as fixes (Upwind lists that as a wrong claim). Judge each build by its own vendor's list. Third, the copy of Java a product carries (Jira, Confluence, Elasticsearch, container images) is separate from the server's system Java. Updating one does not update the other.

Where the code came from: JDK-8268276, "Base64 Decoding optimization for x86 using AVX-512", went into OpenJDK mainline on 25 June 2021, and a crash fix for it (JDK-8273108) landed on 12 December 2021. It was backported to the Java 17 updates on 9 November 2022 and first shipped in 17.0.6 on 17 January 2023. That is why the affected range starts at 17.0.6 and covers every later line. The OpenJDK advisory marks only the 17, 21, 25 and 27 columns for this CVE. The fix is identical in the 17, 21, 25 and 27 update repositories: four lines added to src/hotspot/cpu/x86/stubGenerator_x86_64.cpp that hand a padded tail shorter than one block back to Java. The commit title is "8393212: Base64 optimization improvements", and the commit in the Java 17 update repository is 8ea73158afc9. The mainline (development) fix is still not visible in public repositories.

Same release, other Java fixes: Oracle's November release has 11 Java SE fixes. CVE-2026-114941 (7.0, Compiler, Java 21, 25 and 27) and CVE-2026-114946 (4.8, Compiler, every line including 8 and 11) are separate flaws, and so is CVE-2026-114943 (6.5, Hotspot). Java 8 and 11 hosts still need the November updates. Oracle's baselines are 1.8.0_513-b04 and 11.0.33.1+4.

Quick status check:

```bash
# Running JVMs on this host (run as root to see every user's JVMs). JVMs inside containers don't show here: run it inside each container
jcmd -l
# The live version of one JVM (run as the JVM's user or root)
jcmd <pid> VM.version
# Is the vulnerable path switched on in that JVM?
jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
# Does this machine, or this VM guest, have AVX-512 VBMI? Prints avx512vbmi if it does
grep -o -w avx512vbmi /proc/cpuinfo | head -1
# Kubernetes with Node Feature Discovery: the nodes that have AVX-512 VBMI
kubectl get nodes -l feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI=true
# Java runtimes on disk, including bundled ones (run as root). Compare the full version string
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name release -exec grep -H -E '^(IMPLEMENTOR|JAVA_RUNTIME_VERSION|JAVA_VERSION)=' {} + 2>/dev/null
# Distribution packages (they don't show bundled or tarball runtimes)
dpkg -l 'openjdk-*'
rpm -qa 'java-*openjdk*'
```

- Read the flags line first. Exposed means UseAVX is 3 and UseBASE64Intrinsics is true, on a VBMI CPU, with C2 running. Not exposed means UseBASE64Intrinsics is false, or UseAVX is 2 or lower, or TieredStopAtLevel is 1.
- A release file describes the runtime on disk. After an in-place upgrade a running JVM still runs the old code, so trust `jcmd <pid> VM.version` for live processes.
- If the grep for avx512vbmi prints nothing, that machine or guest doesn't show VBMI. Don't treat lscpu output that merely contains "avx512" as the test: Skylake-SP and Cascade Lake print AVX-512 flags without VBMI, so the Canadian Centre's lscpu check over-reports.
- Root sees every user's JVMs. jcmd needs the JVM's own user or root.
- Distribution package lists don't show bundled or tarball runtimes. The find over release files does.
- Containers carry their own Java. Run the checks inside each container with `docker exec`, and judge an image by the version inside it, not by its tag name. The full assessment steps are in AM I AFFECTED? SELF-ASSESSMENT.

*Sources: Oracle Critical Security Patch Update, Oracle release notes (17.0.6 and the November 2026 builds), OpenJDK advisory, OpenJDK source and fix commits, Red Hat bulletin RHSB-2026-018 and VEX file, Upwind, OpenJ9 issue tracker, Oracle java and jcmd documentation, Canadian Centre for Cyber Security AL26-029*

### Where the fix comes from

Two rules decide whether you are fixed. First, a fix only counts once the JVM has restarted on it. Second, vendors number their builds differently, so the table gives each vendor's fixed build. "Not fixed" means we found no fixed build or advisory at the time shown.

| Platform | Status at 07:59 UTC on 18 November 2026 | Fixed build or version | Notes |
| --- | --- | --- | --- |
| Upstream OpenJDK | Fixed | Tags jdk-17.0.21.1+2, jdk-21.0.13.1+2, jdk-25.0.5.1+2 and jdk-27.0.1.1+4 | Committed to the Java 27 update repository on 14 October 2026 and to the 17, 21 and 25 repositories on 12 November. The mainline (development) fix is still not visible in public repositories |
| Oracle Java SE, the 8 Performance Pack and GraalVM | Fixed | Java SE 17.0.21.1+4, 21.0.13.1+4, 25.0.5.1+4 and 27.0.1.1+4 (all released 17 November 2026). Java 8 Performance Pack 8u513-perf (1.8.0_513-perf-b4). GraalVM for JDK 17.0.21.1, 21.0.13.1 and 25.0.5.1. GraalVM Enterprise Edition 21.3.20.1 | Oracle's notes for 17.0.21.1 say it is not recommended to use that build after Oracle's next quarterly Critical Patch Update on 19 January 2027. The next Critical Security Patch Update is on 15 December 2026 |
| Amazon Corretto | Fixed | 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2 and 27.0.1.1.4 (GitHub releases 17 November, 19:49 to 20:06 UTC) | The Docker images were rebuilt on 17 November (23:50 to 23:56 UTC) under their old tag names, for example 17.0.21-alpine3.24, so a tag name doesn't prove a fixed image. Check java -version inside the image, or pin by digest |
| Amazon Linux | Fixed (17 November) | Amazon Linux 2: ALAS2-2026-4123 (java-17-amazon-corretto 17.0.21.1.2). Amazon Linux 2023: ALAS2023-2026-3478 to 3481 (java-17, -21, -25 and -27-amazon-corretto). Amazon Linux 2027 preview: ALAS2027-2026-371 to 374 | Amazon rates it Important (CVSS 3.1 8.8). Its 22, 23, 24 and 26 packages are marked "No Fix Planned" |
| Azul Zulu | Fixed (17 November) | 17.70.201, 21.54.201, 25.38.201 and 27.30.201. Security-only stream: 17.69.204, 21.53.202 and 25.37.202 | Zulu has its own numbers. The Paketo azul-zulu buildpack merged the fix on 18 November at 02:29 UTC (releases 11.8.3 and 11.8.4) |
| SAP SapMachine | Fixed (17 November) | 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1 | The .1 builds appeared on GitHub between 18:13 and 20:25 UTC |
| Heroku | Fixed, new defaults from 18 November | 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1 | Heroku moved its defaults effective 18 November |
| Arch Linux | Fixed (built 17 November) | jdk17-openjdk 17.0.21.1.u2-1, jdk21-openjdk 21.0.13.1.u2-1, jdk25-openjdk 25.0.5.1.u2-1 and jdk-openjdk 27.0.1.1.u4-1 | n/a |
| Homebrew | Fixed | openjdk 27.0.1.1, openjdk@17 17.0.21.1, openjdk@21 21.0.13.1 and openjdk@25 25.0.5.1 | n/a |
| Google Cloud managed runtimes | Safeguard, not a fix | Masks AVX-512 VBMI for managed Java 17, 21 and 25 on App Engine standard and Cloud Run second generation (including 2nd gen Cloud Run functions) through 30 November 2026 | Does not cover Cloud Run first generation, Cloud Functions (1st gen), App Engine flexible environment, Cloud Run jobs and worker pools, custom containers, or deployments without automatic base image updates |
| Azure Functions | No fix. The default settings keep the path off | None | The Java worker starts the JVM with -XX:+TieredCompilation -XX:TieredStopAtLevel=1, so only C1 runs. Options that re-enable C2 bring the path back. Microsoft has published no advisory |
| Eclipse Temurin and the eclipse-temurin Docker images | Not fixed | The newest GA builds are still 17.0.21+9, 21.0.13+9 and 25.0.5+8 | Adoptium's release-status issue 326 shows testing in progress. This also holds back images built on Temurin, such as the official Jenkins, Tomcat and Kafka images |
| Microsoft Build of OpenJDK | Not fixed | The newest builds are 17.0.21.0.2, 21.0.13.0.2 and 25.0.5.0.2 | n/a |
| Red Hat | Not fixed (no errata) | None | VEX revision 3 (18 November, 01:48 UTC) lists 138 products as known affected: RHEL 8 (java-17 and java-21-openjdk), RHEL 9 (java-17, -21 and -25-openjdk), RHEL 10 (java-21 and java-25-openjdk, plus java-21-ibm-semeru-certified-jdk) and Red Hat build of OpenJDK 17, 21 and 25. Hardened Images (hi/openjdk) is "Fix deferred". Red Hat says OpenJDK 8 and 11 are not affected |
| BellSoft Liberica | Not fixed | None | The newest builds are the affected .0.3 releases (BellSoft's .0.3 builds are dated 26 October) |
| Debian | Not fixed | None | openjdk-17, -21, -25 and -27 are unfixed in bookworm, trixie, forky and sid |
| Ubuntu | Not fixed | None | No CVE entry yet |
| SUSE | Not fixed | None | No CVE page yet |
| Alpine | Not fixed | None | Edge still ships the .0.3 builds |
| GraalVM Community | Not fixed | None | The newest release (3 November) is built on the affected 25.0.5.0.3 |
| Oracle Linux, Rocky Linux and AlmaLinux | Not fixed | None | No advisory yet |
| Fedora | Not checked | Unknown | The page returned a bot challenge |
| IBM Semeru (OpenJ9) | Contested | None | Red Hat's VEX file lists a Semeru package on RHEL 10 as known affected. IBM has made no statement, and OpenJ9 issue 25216 is open with no reply |
| No statement found | Unknown | None | AWS Lambda, Elastic Beanstalk, Azure App Service, Azure Functions (Microsoft), and the product vendors Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache (Tomcat, Kafka, Solr), Cisco, IBM and SAP. Ping Identity and Broadcom could not be checked |

The biggest gaps are Eclipse Temurin and everything built on it, and the Linux distributions: Debian, Ubuntu, Red Hat, SUSE, Alpine, Oracle Linux, Rocky Linux and AlmaLinux. Oracle, Azul and SAP builds come from their download pages and repositories. If your platform has no fixed package yet, apply the stopgap now and update when the advisory lands (the stopgap is in the PROTECTION ROADMAP). For anything marked contested or unknown, check the vendor's own advisory before you rely on a package.

*Sources: vendor and distro pages and trackers as of 07:59 UTC on 18 November 2026 (OpenJDK tags feed, Oracle release notes, Amazon Corretto and Amazon Linux Security Center, Docker Hub, Azul release pages, SapMachine releases, Heroku changelog, Arch Linux and Homebrew package pages, Paketo buildpack releases, Adoptium issue tracker, Microsoft Build of OpenJDK release notes, Red Hat VEX file and bulletin, BellSoft releases, Debian security tracker, Ubuntu, SUSE and Alpine security pages, GraalVM releases, OpenJ9 issue tracker, Google Cloud support bulletins, Azure Functions Java worker issue, AWS security bulletins feed)*

### Where the exposed hardware is

Only JVMs on x86-64 CPUs with AVX-512 VBMI are exposed, so the hardware tells you which hosts to patch first. The bug is in the JVM, not in the processor or the cloud, and the fix is the same everywhere: a fixed Java runtime and a restart. "Inferred" means we drew a conclusion that no vendor states outright.

| Where | What we found | Exposed on the hardware side? |
| --- | --- | --- |
| Processor: Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids and Granite Rapids | Have AVX-512 VBMI | Yes |
| Processor: AMD Zen 4, Zen 5 and Zen 6 (EPYC 9004 and 9005, Ryzen 7000 and later) | Have AVX-512 VBMI | Yes |
| Processor: Intel client Ice Lake, Tiger Lake and Rocket Lake | Have AVX-512 VBMI. Some developer laptops and desktops are in this group | Yes |
| Processor: Centaur CNS and Hygon c86-4g | Have AVX-512 VBMI | Yes |
| Processor: Intel Skylake-SP, Cascade Lake and Cooper Lake | AVX-512 without VBMI | No |
| Processor: Intel Xeon Sierra Forest | No AVX-512 | No |
| Processor: Intel client Alder Lake and later | AVX-512 not supported. Check the flag to be sure | No |
| Processor: AMD Zen 3 and older | Not on the VBMI list | No |
| Processor: ARM64 (AWS Graviton, Ampere) | Not x86-64 | No |
| Cloud: AWS c6i, m6i and r6i | Intel Ice Lake | Yes |
| Cloud: AWS c7i and m7i | Intel Sapphire Rapids | Yes |
| Cloud: AWS c7a and m7a | 4th generation AMD EPYC (Zen 4). The VBMI conclusion is inferred from Zen 4 | Yes (inferred) |
| Cloud: AWS c5 and m5 | Skylake-SP or Cascade Lake, AVX-512 without VBMI | No |
| Cloud: AWS Graviton | ARM | No |
| Cloud: Azure Dv5, Dsv5 and Ev5 | Ice Lake, Sapphire Rapids or Emerald Rapids | Yes |
| Cloud: Azure Dasv6 and Easv6 | AMD EPYC 9004 (Genoa) | Yes |
| Cloud: Azure Dsv6 and Esv6 | Emerald Rapids | Yes |
| Cloud: Google Cloud N2 | Mixed. VBMI only on its Ice Lake variant, and N2 with 96 or more vCPUs requires Ice Lake | Depends on the variant |
| Cloud: Google Cloud C3, C3D, C4, N4, C4D and N4D | Have VBMI | Yes |
| Cloud: Google Cloud N2D | AMD Milan, no AVX-512 | No |

- Red Hat's bulletin names as "most likely" affected: "AWS C6i/M6i/R6i and C7i/M7i/R7a, GCP C3/C3D/C4/C4D/N4/N4D/M3/M4, and Azure Dsv5/Dsv6/Dasv6/Dasv7", plus related D-series v5 to v7 SKUs.
- A virtual machine can hide VBMI. HotSpot turns AVX-512 on only when the CPU reports it and the operating system has enabled its register state, so a hypervisor that masks VBMI removes the path. The same image can be exposed on one node and safe on the next. Run the CPU check inside each guest, and treat any node pool that contains a VBMI node as exposed (our reading).
- HotSpot also defaults to UseAVX=2 on early Skylake steppings, which keeps the AVX-512 code off there.
- This is read from provider pages, processor references, Red Hat's bulletin and the HotSpot source. It is not a survey of real fleets.
- Scale, as a rough guide only: nobody has published an internet-wide count, and version banners say nothing about the CPU. Reuters, citing a government survey, puts Java's share of programming-language use for South Korea's public-sector information systems at 72%. That is a share of language use, not of systems, and it is not evidence of attacks.

*Sources: Wikipedia's AVX-512 page, LLVM's x86 target definitions, AWS, Azure and Google Cloud documentation for the instance families, Red Hat bulletin RHSB-2026-018, Calif's write-up, HotSpot source for the JDK 17 and 21 update repositories, Reuters*

### Products that carry their own Java

Patching the system Java does not fix these. Each product needs its vendor's update or a supported swap of the runtime, and the stopgap flag has to go into the product's own configuration.

| Product | Where its Java comes from | Where the stopgap flag goes |
| --- | --- | --- |
| Jira | The Windows and Linux installers bundle Eclipse Temurin (Jira 11.3.10 and 11.3.11 bundle Temurin 21.0.10_7). tar.gz installs use your own Java | bin/setenv.sh, in JVM_SUPPORT_RECOMMENDED_ARGS. For Docker, the JVM_SUPPORT_RECOMMENDED_ARGS variable |
| Confluence | The installer bundles Temurin (Confluence 11.0.1 bundles 25.0.5.8, and 10.2.20 bundles 21.0.13.9) | bin/setenv.sh, in CATALINA_OPTS. Keep the string ${CATALINA_OPTS} in place |
| Jenkins | The official jenkins/jenkins image carries a Temurin runtime at /opt/java/openjdk and gets the fix only after Adoptium publishes and Jenkins rebuilds | JENKINS_JAVA_OPTS (or JAVA_OPTS). Package installs use a systemd override |
| Keycloak | The official image uses the UBI 9 java-21-openjdk-headless package, so its fix follows Red Hat's errata | JAVA_OPTS_APPEND, never JAVA_OPTS. Setting JAVA_OPTS replaces all of Keycloak's defaults ("JAVA_OPTS already set in environment; overriding default settings") |
| Elasticsearch | Runs its bundled JDK by default. The development branch pins bundled JDK 27.0.1.0.3, an affected build | A file under config/jvm.options.d/ (Debian and RPM: /etc/elasticsearch/jvm.options.d/. Docker: bind mount into /usr/share/elasticsearch/config/jvm.options.d/). Its launcher strips JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS |
| PingFederate | The zip install uses a Java you install | pingfederate/bin/jvm-memory.options |
| Tomcat | Tarball installs use the system Java. The official container images are built on eclipse-temurin | bin/setenv.sh, in CATALINA_OPTS |
| Kafka | Tarball installs use the system Java. The official container images are built on eclipse-temurin | KAFKA_OPTS |
| JFrog Artifactory | Not verified (its documentation was unreachable) | Not verified |

- Calif's code execution claims cover several of these in their default configurations: Keycloak, Jira, Confluence, JFrog Artifactory, Jenkins and PingFederate before login, and Apache Kafka Broker, Apache Solr, Elasticsearch, Gerrit and Spinnaker after login. Its lists are non-exhaustive.
- JAVA_TOOL_OPTIONS is read by the JVM itself and reaches custom launchers. HotSpot skips it only when the process has special privileges, such as a setuid launch. JDK_JAVA_OPTIONS is read only by the java launcher. Elasticsearch strips both, which is why it needs a file, and Keycloak's JAVA_OPTS replaces its defaults, which is why it needs JAVA_OPTS_APPEND.
- We found no statement from Atlassian, Jenkins, Keycloak, JFrog, Elastic or Apache about their products. Ping Identity could not be checked.
- CISA's advice stands: review your software inventory for JDKs and Java runtimes, including those bundled with third party applications or included in container images and appliances.

*Sources: Atlassian documentation for Jira and Confluence, Jenkins Docker image files and documentation, Keycloak container and launcher files, Elastic documentation and build files, Ping Identity documentation, Apache Tomcat and Kafka documentation and image files, CISA alert, Calif's write-up*

---
## ATTACK TIMELINE

### How fast this moved

| When (UTC) | What happened |
| --- | --- |
| 25 June 2021 | JDK-8268276, "Base64 Decoding optimization for x86 using AVX-512", adds the AVX-512 Base64 decoder to OpenJDK mainline |
| 12 December 2021 | A crash fix for it lands (JDK-8273108) |
| 9 November 2022 | The decoder is backported for the Java 17 updates |
| 17 January 2023 | Java 17.0.6 ships with it. 17.0.5 does not contain it |
| 9 September 2026, 09:12 | OpenJDK pull request #32781 ("8392044: AVX-512 Base64 decoder overwrites output buffer on short padded tail") describes the overflow and the fix approach in public |
| 14 October 2026, 10:37 | The fix is committed to the Java 27 update repository, under the bland title "8393212: Base64 optimization improvements" |
| October 2026 | The .0.2 and .0.3 respins ship without the fix (BellSoft's .0.3 builds are dated 26 October) |
| 22 October 2026, 04:13 | Oracle reserves CVE-2026-114938 |
| 4 November 2026, 23:57 | The pull request's author closes it unmerged, 7 hours 45 minutes after a bot's inactivity notice (the author closed it, not the bot) |
| 12 November 2026, 11:42 | The fix is committed to the Java 17, 21 and 25 update repositories |
| 17 November 2026, 14:26 | The Korea Times reports that South Korea's National Intelligence Service has told public institutions to prepare for a critical Java flaw, before disclosure |
| 17 November 2026, about 16:11 | Calif posts on X that details have leaked and that it will publish after Oracle's patch (the time is derived from the post ID, and Tenable relays the post) |
| 17 November 2026, 16:23 | watchTowr publishes an FAQ |
| 17 November 2026, 17:53 | CISA releases KEV catalog 2026.11.17, without this CVE |
| 17 November 2026, 18:13 to 20:25 | SAP SapMachine .1 builds appear on GitHub |
| 17 November 2026, 18:33 | Rapid7 publishes its post |
| 17 November 2026, 19:49 to 20:06 | Amazon Corretto .1 builds appear on GitHub |
| 17 November 2026, 20:27 | The Canadian Centre for Cyber Security issues AL26-029 |
| 17 November 2026, 21:00 | Coordinated release of the OpenJDK advisory and Oracle's Critical Security Patch Update (Calif: "1:00pm PT on Nov 17, 2026") |
| 17 November 2026, 21:32 | CVE record published |
| 17 November 2026, 21:53 | CISA's SSVC entry appears in the CVE record (Exploitation none, Automatable no, Technical impact total), and the oss-security thread opens |
| 17 November 2026, 21:55 | NCSC-NL publishes NCSC-2026-0495 |
| 17 November 2026, 22:18 | NVD receives the record |
| 17 November 2026, 23:00 | VulnCheck makes a full exploit available to its paying Initial Access Intelligence customers |
| 17 November 2026, 23:50 to 23:56 | Rebuilt amazoncorretto images land on Docker Hub, under their old tag names |
| 17 November 2026 | No time given: CISA alert, Google Cloud GCP-2026-082, AWS WAF Known Bad Inputs rule group version 1.28 (Java4Shell rules in Count mode), Fortinet Threat Signal 6668, Qualys QID 389494, Tenable plugins 382091 and 382045, and Snort community rules (the Snort 3 archive is stamped 23:59). Red Hat bulletin RHSB-2026-018 shows created 16:53 and updated 17:14 with no time zone, so it isn't placed on this timeline. South Korea's presidential office holds an emergency meeting |
| 18 November 2026, 01:08 | An Azure Functions Java worker issue (#909) documents that the worker's default flags keep the vulnerable path off |
| 18 November 2026, 01:18 | GreyNoise starts tagging Java4Shell traffic |
| 18 November 2026, 01:48 | Red Hat updates its VEX file (revision 3), with no fixes |
| 18 November 2026, 02:29 | The Paketo azul-zulu buildpack merges the fix (releases follow at 02:48 and 03:57) |
| 18 November 2026, 02:49 | Tenable publishes its FAQ |
| 18 November 2026 | No time given: South Korea's science ministry and KISA advise urgent inspection and updates |
| 18 November 2026, 06:33 to 06:41 | Switzerland's BACS publishes its Java4Shell warning |
| 18 November 2026, 07:00 | A Nuclei template for a version check is proposed (pull request open, not merged) |
| 18 November 2026, 07:18 | GreyNoise counts 3 IPs, 53 requests and 0 successful intrusions |
| 18 November 2026, 08:00 | Data cut-off for this analysis. Not yet fixed: Eclipse Temurin, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux |
| 30 November 2026 | Coming: Google's CPU-feature masking on managed Java runtimes ends |
| 15 December 2026 | Coming: Oracle's next Critical Security Patch Update |
| 19 January 2027 | Coming: Oracle's next quarterly Critical Patch Update. Oracle's 17.0.21.1 notes say it is not recommended to use that build after it |

Critical insight: the problem and the fix approach sat in a public OpenJDK pull request from 9 September 2026, about ten weeks before the release. The pull request says the stub "stores past the logical output length before returning to Java, corrupting the heap". The fix itself went into the Java 27 update repository on 14 October under the bland title "8393212: Base64 optimization improvements", which says nothing about security, and it sat there for more than a month before the release. The pull request's author closed it unmerged on 4 November, and the Java 17, 21 and 25 update repositories got the fix on 12 November, five days before the release. On release day the news moved faster than the fixes. South Korea's intelligence service had warned public institutions by 14:26 UTC, Calif said at about 16:11 that details had leaked, and the Canadian Centre published its alert at 20:27, all before the coordinated release at 21:00. VulnCheck had a full exploit for paying customers two hours after the release, and GreyNoise started tagging Java4Shell traffic about four hours after it. At the 08:00 UTC cut-off on 18 November, 11 hours after the release, 12 Java vendors and Linux distributions still had no fixed build, Eclipse Temurin and Red Hat among them. For an internet-facing identity or build server on exposed hardware, "we'll patch it next window" isn't a plan.

*Sources: The OpenJDK project (pull request, update repositories and tags, advisory), Oracle Critical Security Patch Update and Java SE release notes, the CVE record, NVD, CISA (alert, KEV catalog and the SSVC entry in the CVE record), Calif's write-up and its post on X as relayed by Tenable, the Korea Times, watchTowr, Rapid7, VulnCheck, GreyNoise, Tenable, Qualys, Fortinet, Red Hat, Google Cloud, the AWS WAF managed rules changelog, Snort community rules, Amazon Corretto, SAP SapMachine, BellSoft and Paketo repositories, Docker Hub, the Azure Functions Java worker issue tracker, the Canadian Centre for Cyber Security, NCSC-NL, Switzerland's BACS, the Nuclei pull request list*

### Who's attacking

No exploitation in the wild has been confirmed, so there is nobody to attribute. No source names a threat actor, campaign or malware. Here is what each source said by 08:00 UTC on 18 November:

| Source | What they said or showed | Confidence |
| --- | --- | --- |
| CISA (KEV and SSVC) | Not listed in KEV (catalog 2026.11.17, released at 17:53 UTC on 17 November, before the CVE record was published). Its entry in the CVE record (21:53 UTC) gives SSVC: Exploitation none, Automatable no, Technical impact total | Negative. A snapshot from the day of release |
| Canadian Centre for Cyber Security | AL26-029 (20:27 UTC on 17 November): "The Cyber Centre is not aware of active exploitation at this time, but that can change quickly." | Negative, and the source itself warns that it can change |
| Tenable, Qualys and Horizon3 | Report no exploitation | Negative. Vendor statements |
| VulnCheck | Says the bug is "not known to be exploited in the wild at time of writing." Also says "A full RCE exploit for CVE-2026-114938 is available to Initial Access Intelligence customers as of 6 PM EST on November 17" (23:00 UTC), shipped "with a version scanner, a PCAP, and Snort, Suricata, Sigma, and YARA rules." From its own testing: "A single request usually will not crash a default-configured server... but a simple burst of requests reliably brought the service down in our testing." | Vendor statement. The exploit is not public |
| GreyNoise | Its Java4Shell tracker (last updated 07:18 UTC on 18 November) shows "3 IPs Sending Java4Shell-Shaped Base64", "53 Java4Shell-Shaped Requests", "0 Successful Intrusions" and "Block candidates (0)". Its two tags were first seen at 01:18 UTC | Sensor data. Scanner traffic, with no intrusion counted |
| Calif | Says its product chains are private: "The weaponized chains for individual products stay private until everyone has had a chance to upgrade. We will publish them later." Says it achieved code execution in default configurations before login in Keycloak, Atlassian Jira, Atlassian Confluence, JFrog Artifactory, Jenkins and PingFederate, and after login in Apache Kafka Broker, Apache Solr, Elasticsearch, Gerrit and Spinnaker. "The lists are non-exhaustive", and "there is no universal exploit". It also publishes a bounded self-test that checks the JDK and CPU it runs on, not whether an application is reachable | Claim by the researchers. Not public. The labs that published results reproduced crashes and a memory leak, not code execution |
| Immersive, via Tenable | Tenable relays that Kevin Breen of Immersive said on X they had developed a working exploit that "has to be adapted to each application". The post does not say it was released | Secondhand. A social media post relayed by a vendor |
| Independent labs | Upwind reproduced the overflow on an AWS c6i instance (Intel Ice Lake). Upwind says that with an exact-size output buffer the overflow corrupted the next object in 97% of rounds and eventually crashed the JVM. Blackpoint, per The Hacker News, "crashed a test Spring Boot application by sending about 28,300 malformed login requests over roughly 20 seconds", and its memory-read test "worked in all 30 runs"; it "did not reproduce remote code execution". The Hacker News: "other labs have so far reproduced crashes and a memory leak but not the code execution." | Lab results. Blackpoint's reach us through The Hacker News (secondary) |
| Expert readings | Pentestit: "Code execution is still only Calif's claim". Equixly: "Denial of service is the realistic impact." watchTowr says it rated the CVE highly likely to be exploited in the wild when it was disclosed. VulnCheck calls a crash "trivial" if you can find and reach a sink that uses the vulnerable Base64 decode logic, and says "we don't anticipate that CVE-2026-114938 will be easily or widely exploitable", but "adversaries are likely to find narrow but functional paths to RCE in specific applications". Upwind lists the idea that it is only a crash as a wrong claim, because Calif demonstrated heap disclosure and code execution | Opinion, not attack data |
| Metasploit and Nuclei | No Metasploit module. A Nuclei version-check template was proposed at 07:00 UTC on 18 November (pull request open, not merged) | Negative |
| GitHub | 25 repositories mention the CVE (07:46 UTC on 18 November). By what they claim: 12 tools, scanners, detection or mitigation projects, 5 labs or local reproductions, 2 that claim exploits, 2 write-ups and 4 empty | Not verified. Treat as untrusted |
| Government CERTs and agencies | The Canadian Centre for Cyber Security titles AL26-029 "Critical vulnerability impacting Oracle Java". CISA's alert calls the bug "This critical memory-corruption vulnerability". South Korea's National Intelligence Service rated it critical (Korea Times), the presidential office held an emergency meeting, and the science ministry and KISA advised urgent inspection and updates. Switzerland's BACS calls it a critical vulnerability. NCSC-NL (NCSC-2026-0495) rates it medium likelihood, high impact (M/H). It says the bug is not easy to abuse because successful exploitation has several requirements | Advisories only, no attack data |

Where the sources disagree: Calif claims code execution before login in six products, and VulnCheck says it holds a full exploit for paying customers, while the independent labs that published results reproduced crashes and a memory leak but not code execution. Nothing public settles it.

Our reading: crashes are the most likely harm this week, the memory read can be quiet, and code execution needs work tailored to each product. The signs that this has changed would be Calif's release of its chains, a merged Nuclei template, a Metasploit module or a KEV listing.

Absence of reports is weak evidence, and the data stops at 08:00 UTC on 18 November, 11 hours after the release. There is no list of attacker IPs or attack pattern to give you, and no indicators of compromise have been published beyond scanner traffic. GreyNoise's tracker is the place to watch, and we don't list the addresses. Prophet Security warns: "Many frameworks catch the exception and reject the request without logging it, so a quiet application log does not rule out an attempt." Skip the GitHub repositories too. Nobody has verified them, and Pentestit's advice is "Read any script before you run it." To find out whether you're exposed, use the checks in AM I AFFECTED? SELF-ASSESSMENT.

*Sources: CISA KEV catalog, alert and the SSVC entry in the CVE record, Canadian Centre for Cyber Security, Tenable, Qualys, Horizon3, VulnCheck, GreyNoise, Calif, Upwind, The Hacker News (reporting Blackpoint), Pentestit, Equixly, watchTowr, the Metasploit and Nuclei pull request lists, GitHub repository search, Korea Times, NCSC-NL, Switzerland's BACS, Prophet Security*

### Global impact statistics

- **No count exists** of internet-facing JVMs that carry this bug on VBMI hardware. No source counts them, and this analysis gives none. A count of Java versions couldn't size the exposure anyway, because version banners say nothing about the CPU or the JVM flags.
- **3 IPs, 53 requests and 0 successful intrusions** is GreyNoise's count of Java4Shell-shaped traffic (last updated 07:18 UTC on 18 November). Its two tags were first seen at 01:18 UTC, and its tracker shows "Block candidates (0)". It counts scanner traffic, not victims.
- **72%** is Java's "share of programming language use for information systems" in South Korea's public sector, from a government survey that Reuters reports. It is a share of language use, not of systems, and it is not evidence of attacks.
- **No EPSS score** exists yet, and the CVE is **not listed** in CISA KEV (catalog 2026.11.17). NVD shows the status "Received", with no CPE data and no NVD score of its own (it shows Oracle's 8.1).
- **25** GitHub repositories mentioned the CVE at 07:46 UTC on 18 November. That is a proxy for attention, not exposure. None is verified.
- **138** products are listed as known affected in Red Hat's VEX file (revision 3, 01:48 UTC on 18 November), with no fixes. It counts products, not exposed servers.
- **12** Java vendors and Linux distributions had no fixed build at the cut-off, 11 hours after the release: Eclipse Temurin, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux.
- **Scanner coverage** exists (Qualys QID 389494, Tenable plugins 382091 and 382045, a Rapid7 authenticated check), but a version scanner can't see the CPU or the JVM flags, and dependency scanners can't see the runtime.

*Sources: GreyNoise tracker, Reuters, FIRST EPSS API, CISA KEV catalog, NVD, GitHub repository search, Red Hat VEX file, Qualys, Tenable, Rapid7, the vendor and distribution pages behind the patch status*

---

## AM I AFFECTED? SELF-ASSESSMENT

The checks below are manual and read-only. Run the host commands as root where a comment says so, or they may miss JVMs and files you can't read. `jcmd` needs the JVM's own user or root.

### Quick 5-minute assessment

**STEP 1: Where does Java run? (2 minutes)**

Java hides in more places than most inventories list. CISA's alert says: "Review your software inventory for JDKs and Java runtimes, including those bundled with third-party applications or included in container images and appliances. Note: JDKs and Java runtimes may not appear as separate entries in software inventories." Start on each host:

```bash
# Running JVMs on this host (run as root to see every user's JVMs). JVMs inside containers don't show here: run it inside each container
jcmd -l
# Java processes with their owner and process ID. On a Linux container host this also lists JVMs started inside containers (run as root)
ps -eo user,pid,args | grep -E '[j]ava'
# The program a process runs, which shows whether it is a bundled or a system runtime (Linux, run as the JVM's user or root)
readlink -f /proc/<pid>/exe
# Java runtimes on disk, including bundled ones (run as root). Compare the full version string
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name release -exec grep -H -E '^(IMPLEMENTOR|JAVA_RUNTIME_VERSION|JAVA_VERSION)=' {} + 2>/dev/null
# Distribution packages (they don't show bundled or tarball runtimes)
dpkg -l 'openjdk-*'
rpm -qa 'java-*openjdk*'
```

A container keeps the Java it was built with, and `jcmd -l` on the host doesn't see inside it, so check each container from the inside. On Kubernetes, run the same `jcmd` and `java -version` checks inside each pod's container. Developer laptops and desktops count too:

```bash
# Java version inside a running container (replace <container> with its name or ID, run as root)
docker exec <container> java -version
# A laptop or desktop: the Java on the PATH. It may not be the runtime an application uses
java -version
# macOS with Homebrew: installed OpenJDK versions
brew list --versions | grep -i openjdk
```

Inventories miss some places, so look there too: golden images, VM templates and autoscaling launch configurations that still carry an affected runtime, test and staging servers that face the internet, build and CI servers, container images, and products and appliances that carry their own Java. You can't run commands on an appliance, so ask the vendor in writing which Java build it carries and when its fix ships. At the cut-off we found no statement from AWS Lambda, Elastic Beanstalk, Azure App Service or Azure Functions (Microsoft), nor from the product vendors Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache (Tomcat, Kafka, Solr), Cisco, IBM and SAP. Ping Identity and Broadcom could not be checked.

Products that carry their own Java keep it when you patch the system Java:

| Product | Where its Java comes from |
| --- | --- |
| Jira | The Windows and Linux installers bundle Eclipse Temurin (Jira 11.3.10 and 11.3.11 bundle Temurin 21.0.10_7). tar.gz installs use your own Java |
| Confluence | The installer bundles Temurin (Confluence 11.0.1 bundles 25.0.5.8, and 10.2.20 bundles 21.0.13.9) |
| Jenkins | The official jenkins/jenkins image carries a Temurin runtime at /opt/java/openjdk and gets the fix only after Adoptium publishes and Jenkins rebuilds |
| Keycloak | The official image uses the UBI 9 java-21-openjdk-headless package, so its fix follows Red Hat's errata |
| Elasticsearch | Runs its bundled JDK by default. The development branch pins bundled JDK 27.0.1.0.3, an affected build |
| PingFederate | The zip install uses a Java you install |
| Tomcat and Kafka | Tarball installs use the system Java. Their official container images are built on eclipse-temurin |
| JFrog Artifactory | Not verified: its documentation was unreachable |

A vulnerability scanner can give you a starting list (Qualys QID 389494, Tenable plugins 382091 and 382045), but it can't see the CPU or the JVM flags, and dependency scanners can't see the runtime. Use a scanner to find hosts, not to clear them.

*Sources: CISA alert, Atlassian, Jenkins, Keycloak, Elastic, Ping Identity, Apache Tomcat and Kafka documentation and container build files, Docker library images, Google Cloud, AWS and Microsoft pages, Qualys and Tenable plugin lists (checked on 18 November 2026)*

---

**STEP 2: Does each build carry the fix? (1 minute)**

Start with the version-number traps, because they fool scanners and people alike. The fix is the .1 build. Run these on the host or inside the container, then read the result against the list below:

```bash
# The live version of one JVM (run as the JVM's user or root)
jcmd <pid> VM.version
# Container: the version inside the running container (replace <container> with its name or ID, run as root)
docker exec <container> java -version
# Debian and Ubuntu: installed package version, and the version your repositories offer (replace 21 with the Java version you run)
dpkg -s openjdk-21-jre-headless | grep '^Version'
apt-cache policy openjdk-21-jre-headless
# RHEL family and Amazon Linux 2023: installed Java packages
dnf list installed 'java-*'
# Amazon Linux 2 and other RPM systems: installed Java packages
rpm -qa 'java-*'
# Alpine: installed package versions
apk info -v | grep openjdk
# Homebrew: installed version
brew list --versions openjdk@21
```

**Interpretation:**

- Fixed builds: OpenJDK tags jdk-17.0.21.1+2, jdk-21.0.13.1+2, jdk-25.0.5.1+2 and jdk-27.0.1.1+4. Oracle Java SE 17.0.21.1+4, 21.0.13.1+4, 25.0.5.1+4 and 27.0.1.1+4, all released 17 November 2026, and 8u513-perf (1.8.0_513-perf-b4) for the Java 8 Performance Pack. Oracle GraalVM for JDK 17.0.21.1, 21.0.13.1 and 25.0.5.1, and GraalVM Enterprise Edition 21.3.20.1. Amazon Corretto 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2 and 27.0.1.1.4. Azul Zulu 17.70.201, 21.54.201, 25.38.201 and 27.30.201 (the security-only stream is 17.69.204, 21.53.202 and 25.37.202). SAP SapMachine 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1. What every other platform has published (Amazon Linux, Arch Linux, Homebrew, Heroku, Paketo and more) is in the RISK DASHBOARD.
- Trap 1, the October respins: the builds ending in .0.2 and .0.3 (17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 and 27.0.1.0.3) look newer than the October releases but are the last vulnerable builds.
- Trap 2, vendor numbering: Corretto adds a fifth field (17.0.21.1.2), Azul Zulu has its own numbers (17.70.201), and some write-ups wrongly cite 17.0.11 and 21.0.3 as fixes (Upwind lists that as a wrong claim). Judge each build by its own vendor's list.
- Trap 3, the product's own Java: the copy of Java that Jira, Confluence, Elasticsearch and container images carry is separate from the server's system Java. Updating one does not update the other.
- Trap 4, Docker tags: Amazon rebuilt its amazoncorretto images on 17 November (23:50 to 23:56 UTC) under their old tag names, for example 17.0.21-alpine3.24, so a tag name doesn't prove a fixed image. Check `java -version` inside the image, or pin by digest.
- Affected, per Oracle: Java SE 8u511b33-perf (the Java 8 Performance Pack only), 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 and 27.0.1.0.3, Oracle GraalVM for JDK 17.0.21.0.3 and 21.0.13.0.3, and GraalVM Enterprise Edition 21.3.20.0.3. Earlier builds in each line back to the start of the code are affected too. The decoder came in with JDK-8268276 and shipped in Java 17.0.6, so the affected range is Java 17.0.6 and later, every 18 to 27 release, and Oracle's Java 8 Performance Pack.
- Not affected: Java 11 has no AVX-512 decode intrinsic (only an encode one), and the 2021 change was never backported. Standard Java 8 is not affected (only the Performance Pack build), and neither is Java 17.0.0 to 17.0.5. Red Hat: "Customers running OpenJDK 8 or OpenJDK 11 are also not affected, as these versions do not contain the vulnerable code path." The OpenJDK advisory marks only the 17, 21, 25 and 27 columns for this CVE. These lines still need the November updates, which fix other flaws (Oracle's baselines for Java 8 and 11 are 1.8.0_513-b04 and 11.0.33.1+4).
- Retired lines get no fix: 18 to 20, 22 to 24 and 26. Amazon marks its 22, 23, 24 and 26 packages "No Fix Planned". Move them to 21.0.13.1, 25.0.5.1 or 27.0.1.1.
- Contested or unknown: IBM Semeru (OpenJ9). Red Hat's VEX file lists java-21-ibm-semeru-certified-jdk on RHEL 10 as known affected, while IBM has made no statement and OpenJ9 issue 25216 is open with no reply. GraalVM Native Image is probably not affected, because native executables don't run HotSpot's C2 compiler (inferred), but no vendor has said so.
- Not fixed at the cut-off (08:00 UTC on 18 November): Eclipse Temurin and its Docker images (newest GA still 17.0.21+9, 21.0.13+9 and 25.0.5+8; Adoptium's release-status issue 326 shows testing in progress, which also holds back images built on Temurin, such as the official Jenkins, Tomcat and Kafka images). Microsoft Build of OpenJDK (newest builds 17.0.21.0.2, 21.0.13.0.2 and 25.0.5.0.2). Red Hat (no errata, and the bulletin's status is "Ongoing"; VEX revision 3 lists 138 products as known affected, from RHEL 8, 9 and 10 packages to Red Hat build of OpenJDK 17, 21 and 25, and Hardened Images (hi/openjdk) is "Fix deferred"). BellSoft Liberica (newest builds are the affected .0.3 releases). Debian (openjdk-17, -21, -25 and -27 unfixed in bookworm, trixie, forky and sid). Ubuntu (no CVE entry yet) and SUSE (no CVE page yet). Alpine (edge still ships the .0.3 builds). GraalVM Community (the newest release, 3 November, is built on the affected 25.0.5.0.3). Oracle Linux, Rocky Linux and AlmaLinux (no advisory yet). Fedora was not checked, and IBM Semeru has no statement. For a build from any of these, a package version can't clear it yet: go to STEP 3, and use the stopgap in For technical teams while you wait.

Fixed: go to STEP 5: Is the fixed build or the flag actually running? Vulnerable or unsure: go to STEP 3: Is the hardware exposed?

*Sources: Oracle Critical Security Patch Update and Java SE release notes, the OpenJDK advisory and update repository tags, Red Hat bulletin RHSB-2026-018 and VEX file, Amazon Linux advisories and Corretto releases, Azul, SAP SapMachine, Adoptium, Microsoft, BellSoft, Debian, Alpine and GraalVM release pages, the OpenJ9 issue tracker, HotSpot source, Upwind (checked on 18 November 2026)*

---

**STEP 3: Is the hardware exposed? (1 minute)**

The bug sits in code that only runs on x86-64 processors with AVX-512 VBMI. The HotSpot source tests for avx512vbmi and avx512bw, and Java 17 also needs avx512vl before it turns the intrinsic on by default. A JVM is exposed only when the CPU it sees has those features and UseAVX is 3, which is the default on those CPUs. Run the check inside each virtual machine, because a hypervisor can hide the feature from a guest.

```bash
# Does this machine, or this VM guest, have AVX-512 VBMI? Prints avx512vbmi if it does
grep -o -w avx512vbmi /proc/cpuinfo | head -1
# Kubernetes with Node Feature Discovery: the nodes that have AVX-512 VBMI
kubectl get nodes -l feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI=true
```

**Interpretation:**

- The grep prints avx512vbmi when the CPU the JVM sees has the feature, and prints nothing on ARM64 and on x86-64 chips without it. It reads `/proc/cpuinfo`, so it is for Linux. On a macOS or Windows laptop, compare the processor model with the lists below.
- The Canadian Centre's `lscpu | grep avx512` check over-reports, because Skylake-SP and Cascade Lake print AVX-512 flags without VBMI. Calif's four-flag check (avx512f, avx512bw, avx512vbmi, bmi2) over-asks, because bmi2 is not a gate, but it gives no wrong answer on real hardware.
- Virtual machines: HotSpot turns AVX-512 on only when the CPU reports it and the OS has enabled its register state, so a hypervisor that masks VBMI removes the path. The same image can be exposed on one node and safe on the next. Run the CPU check inside each guest, and treat any node pool that contains a VBMI node as exposed (our reading).
- Kubernetes: the node label exists only where Node Feature Discovery runs. Where it doesn't, run the grep on a node from each pool.
- **Has AVX-512 VBMI:** Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids and Granite Rapids. AMD Zen 4, Zen 5 and Zen 6 (EPYC 9004 and 9005, Ryzen 7000 and later). Intel client Ice Lake, Tiger Lake and Rocket Lake, so some developer laptops and desktops are exposed. Also Centaur CNS and Hygon c86-4g.
- **No AVX-512 VBMI:** ARM64 (AWS Graviton, Ampere). Intel Skylake-SP, Cascade Lake and Cooper Lake (AVX-512 without VBMI). Intel Xeon Sierra Forest (no AVX-512). Intel client Alder Lake and later (AVX-512 not supported, but check the flag to be sure). AMD Zen 3 and older. HotSpot also defaults to UseAVX=2 on early Skylake steppings.
Cloud families, from each provider's own pages:

| Provider | Has AVX-512 VBMI | Does not |
| --- | --- | --- |
| AWS | c6i, m6i and r6i (Ice Lake), c7i and m7i (Sapphire Rapids), c7a and m7a (4th gen AMD EPYC, Zen 4; the VBMI conclusion is inferred from Zen 4) | c5 and m5 (Skylake-SP or Cascade Lake). Graviton is ARM |
| Azure | Dv5, Dsv5 and Ev5 (Ice Lake, Sapphire Rapids or Emerald Rapids), Dasv6 and Easv6 (AMD EPYC 9004, Genoa), Dsv6 and Esv6 (Emerald Rapids) | Not checked |
| Google Cloud | C3, C3D, C4, N4, C4D and N4D. N2 is mixed: VBMI only on its Ice Lake variant, and N2 with 96 or more vCPUs requires Ice Lake | N2D (AMD Milan) has no AVX-512 |

- Red Hat's bulletin names these as "most likely" affected: "AWS C6i/M6i/R6i and C7i/M7i/R7a, GCP C3/C3D/C4/C4D/N4/N4D/M3/M4, and Azure Dsv5/Dsv6/Dasv6/Dasv7", plus related D-series v5 to v7 SKUs.
- Google: "As an interim platform safeguard through November 30, 2026, Google has masked AVX-512 VBMI for managed Java 17, 21, and 25 runtimes on the App Engine standard environment and the Cloud Run second generation execution environment (including 2nd gen Cloud Run functions)". It "does not cover the Cloud Run first generation execution environment, Cloud Functions (1st gen), App Engine flexible environment, Cloud Run jobs and worker pools, custom containers, or deployments without automatic base image updates". Heroku moved its defaults to 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, effective 18 November. We found no statement from AWS Lambda or Elastic Beanstalk.
- Our reading: the usual rule of thumb runs backwards here. The newest Java on the newest x86 hardware is exposed, and teams still on older Intel chips or on ARM are clear by accident.

*Sources: Red Hat bulletin RHSB-2026-018, Calif's write-up, HotSpot source at the 17.0.21 and 21.0.13 tags, Wikipedia's AVX-512 table, LLVM's x86 processor definitions, AWS, Azure and Google Cloud documentation, Google Cloud security bulletins, Heroku changelog (checked on 18 November 2026)*

---

**STEP 4: Is the vulnerable path switched on? (30 seconds)**

Hardware is only half of it. The path also needs the Base64 intrinsic on, which is the default, and the C2 compiler running, which is the default for long-running servers. Only C2 inlines the stub. C1 does not.

```bash
# Is the vulnerable path switched on in that JVM? (run as the JVM's user or root)
jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
```

**Interpretation:**

- Exposed means UseAVX is 3 and UseBASE64Intrinsics is true, on a VBMI CPU, with C2 running.
- Not exposed means UseBASE64Intrinsics is false, or UseAVX is 2 or lower, or TieredStopAtLevel is 1 (only C1 runs).
- Azure Functions: the Java worker starts the JVM with -XX:+TieredCompilation -XX:TieredStopAtLevel=1, so only C1 runs and the default configuration doesn't reach the stub. Options that re-enable C2 (for example -XX:TieredStopAtLevel=4 or -XX:-TieredCompilation in JAVA_OPTS, languageWorkers__java__arguments or _JAVA_OPTIONS) bring it back. The issue checked whether the intrinsic was used. It did not test memory corruption, and Microsoft has published no advisory.
- The basic and URL-safe decoders (Base64.getDecoder() and Base64.getUrlDecoder()) reach the stub once C2 has compiled the decode path. The MIME decoder skips the vector path. Red Hat names typical carriers: HTTP Basic credentials, SAML artifacts, CSRF tokens and MIME encoded words.
- Not yet known, from any source: the C2 compile threshold, and whether the decode(ByteBuffer) and wrap(InputStream) forms reach the stub. So don't read a freshly started JVM as safe, and don't clear an application because it uses those forms (our reading).
- A Java program with no service of its own can still be exposed: Calif says "A Java program that opens a TLS connection to a malicious server can be compromised, even if it exposes no service of its own." Nobody has published how that path works.

| What you found | Priority |
| --- | --- |
| Internet-facing service on an affected build, on x86-64 hardware with AVX-512 VBMI, with the JVM defaults left on (intrinsic on, C2 running). Start with identity and single sign-on servers, CI and artifact servers, and Jira and Confluence. Don't lower the rating for a WAF or proxy in front: it is a layer, not a fix | CRITICAL. Patch and restart first, today. Where no fixed build exists yet, apply the stopgap and restart |
| The same setup on an internal-only service | HIGH. Patch this week. An internal service is exposed to everyone who can reach that network, partners and VPN users included |
| A Java program on that hardware, on an affected build, that opens TLS connections to servers you don't control (the client-side variant) | HIGH. Patch this week |
| An affected build on ARM64, or on x86-64 without VBMI | Not exposed today. Patch in the normal window, because workloads move between machine types |
| The vulnerable path is off in the running JVM: UseBASE64Intrinsics false, UseAVX 2 or lower, or only C1 running | Not exposed to this bug while that setting holds. Patch anyway, and remove the flag once the fixed runtime is confirmed (Red Hat, Google) |
| Standard Java 8, Java 11 or Java 17.0.0 to 17.0.5 | Not affected by this CVE. Take the November update in the normal window anyway, because Oracle's November release has 11 Java SE fixes. CVE-2026-114941 (7.0, Compiler, Java 21, 25 and 27) and CVE-2026-114946 (4.8, Compiler, every line including 8 and 11) are separate flaws, and so is CVE-2026-114943 (6.5, Hotspot) |

Containers and managed Java platforms count as internet-facing when their ports are reachable from untrusted networks.

*Sources: Red Hat bulletin RHSB-2026-018, HotSpot source at the 17.0.21 and 21.0.13 tags, the Azure Functions Java worker issue tracker, configuration and Microsoft documentation, Calif's write-up, Oracle Critical Security Patch Update, Google Cloud security bulletins (checked on 18 November 2026)*

---

**STEP 5: Is the fixed build or the flag actually running? (30 seconds)**

```bash
# The live version of each JVM, after the restart (run as the JVM's user or root)
jcmd <pid> VM.version
# Every Java process with its start time (run as root). A JVM that started before the update still runs the old runtime
ps -eo user,pid,lstart,args | grep -E '[j]ava'
# After the restart, confirm the running JVM picked up the flag (run as the JVM's user or root)
jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
# Container: the version inside the running container (replace <container> with its name or ID, run as root)
docker exec <container> java -version
```

A package update puts new files on disk and leaves a running JVM on the old code until it restarts. A release file describes the runtime on disk, and `java -version` reads the Java on the PATH, so on their own they prove nothing about a live process. `jcmd <pid> VM.version` asks the running JVM. If a JVM started before the update, restart the service (the commands are in For technical teams). A container works the same way: it keeps the Java it was built with, so rebuild your image on a fixed base, redeploy it, and run the version check inside the new container. Pin the digest after you have checked it.

Where a stopgap flag is your protection, the flag has to be in the running JVM too, and where you put it decides whether it works. JAVA_TOOL_OPTIONS is read by the JVM itself (it prints "Picked up JAVA_TOOL_OPTIONS") and reaches custom launchers, but HotSpot skips it when the process has special privileges, such as a setuid launch. JDK_JAVA_OPTIONS is read only by the java launcher. Products with their own launchers need the flag in their own configuration. Elasticsearch strips JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS, and Keycloak's JAVA_OPTS replaces all of Keycloak's defaults. Run the flags check after the restart and read the result: UseBASE64Intrinsics false, or UseAVX 2 or lower, means the stopgap took.

*Sources: Red Hat bulletin RHSB-2026-018, Google Cloud security bulletins, Oracle java and jcmd documentation, the Elasticsearch and Keycloak launch scripts, HotSpot source (checked on 18 November 2026)*

---

### Full vulnerability checklist

**You are VULNERABLE if ALL of these are true:**

- [ ] A JVM runs an affected HotSpot build: Java 17.0.6 or later, any 18 to 27 release, or Oracle's Java 8 Performance Pack, on a build older than its vendor's fix. The .0.2 and .0.3 respins count as vulnerable. A fixed build that was installed but never restarted into the running JVM counts too
- [ ] The CPU the JVM sees is x86-64 with AVX-512 VBMI (the grep in STEP 3 prints avx512vbmi inside the guest or on the host that runs it), and UseAVX is 3, which is the default on those CPUs
- [ ] UseBASE64Intrinsics is true (the default) and C2 is running (TieredStopAtLevel is not 1), which is the default for long-running servers
- [ ] The application passes attacker-supplied Base64 to the basic or URL-safe decoder
- [ ] An untrusted party can reach that input: the internet, a partner network or a VPN for a service, or a TLS connection to a server you don't control for a Java program that runs no service of its own

**Your risk is higher if ANY of these also apply:**

- [ ] The service is one Calif says it exploited before login (Keycloak, Atlassian Jira, Atlassian Confluence, JFrog Artifactory, Jenkins, PingFederate) or after login (Apache Kafka Broker, Apache Solr, Elasticsearch, Gerrit, Spinnaker). Calif adds that "The lists are non-exhaustive", and it also names sample apps on Apache Struts and Spring Boot
- [ ] It is an identity or single sign-on server, a CI or artifact server, or Jira or Confluence, and it faces the internet
- [ ] The JVM holds secrets in memory, such as signing keys, session tokens or stored credentials. The memory read can leave no crash (our reading)
- [ ] The JVM runs in a node pool or cluster where any node has VBMI. The same image can be exposed on one node and safe on the next
- [ ] Java is bundled inside a product, image or appliance whose vendor hasn't shipped a fix or said anything (Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache, Cisco, IBM and SAP at the cut-off), or whose runtime comes from a vendor with no fixed build yet (Eclipse Temurin, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux, AlmaLinux)
- [ ] The JVM runs on a retired line (18 to 20, 22 to 24, 26), which gets no fix
- [ ] You count on a WAF, a proxy or an input size limit as the only protection. Size limits alone won't stop it, because the malformed input that triggers it is short (our reading of Endor Labs' description of the trigger), and AWS's Java4Shell rules log and don't block until you change the action
- [ ] A stopgap flag sits where the JVM ignores it, such as in JAVA_TOOL_OPTIONS on Elasticsearch, or in Keycloak's JAVA_OPTS, which replaces its defaults
- [ ] The platform's own safeguard is partial or temporary: Google's VBMI masking covers only some managed runtimes and ends on 30 November 2026

Nothing on the second list is a reason to skip the update. The fix is four lines added to one HotSpot source file (src/hotspot/cpu/x86/stubGenerator_x86_64.cpp), and Oracle's November release has 11 Java SE fixes in all.

*Sources: Oracle Critical Security Patch Update, the OpenJDK advisory and fix commit, Calif's write-up, Red Hat bulletin RHSB-2026-018, Qualys, Endor Labs, AWS WAF managed rules changelog, Google Cloud security bulletins, vendor and distribution pages (checked on 18 November 2026)*

---

### You are SAFE if:

- [ ] Every Java runtime you run is on a fixed build for its vendor (17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 or the vendor's own equivalent, judged by the vendor's list and not by the number), or on a line this bug doesn't reach (standard Java 8, Java 11, Java 17.0.0 to 17.0.5)
- [ ] Every patched JVM was restarted, and `jcmd <pid> VM.version` shows the fixed build (a runtime on disk doesn't count)
- [ ] Container images were rebuilt on a fixed base and redeployed, and `docker exec <container> java -version` shows the fixed build (a tag name doesn't prove it, and a rebuilt image that isn't running doesn't count)
- [ ] Products that carry their own Java (Jira, Confluence, Elasticsearch and others) run a build their vendor has confirmed fixed, or a supported swap of the runtime. Updating the system Java does not change them
- [ ] Retired lines (18 to 20, 22 to 24, 26) were moved to 21.0.13.1, 25.0.5.1 or 27.0.1.1
- [ ] For JVMs you can't patch yet: the flags check on the running JVM shows UseBASE64Intrinsics false, or UseAVX 2 or lower. A flag that sits in a config file or a shell variable but not in the running JVM doesn't count. That closes this bug's path, but not the other flaws fixed in the November updates, so still patch in the normal window
- [ ] The only hosts running affected builds are ARM64 or x86-64 without AVX-512 VBMI, checked inside each guest and across each node pool. That is not exposed today, but workloads move between machine types, so still patch in the normal window

**IMPORTANT:** Network controls, WAF rules and input size limits do not fix the bug. Only a fixed runtime does, and only after the JVM restarts. The stopgap flag removes the path while it is set, and it needs a restart too. No network control recovers data already read from memory.

A clean scanner report still proves little. A version scanner can't see the CPU or the JVM flags, and dependency scanners can't see the runtime. NVD shows the record as "Received", with no product data and no score of its own (it shows Oracle's 8.1), so tools that read NVD alone miss it, and the Ubuntu, SUSE and Alpine feeds have no entry. Semgrep: "A WAF rule, a lack of alerts or a lack of crashes does not prove that a runtime is patched or that no attempt occurred." Check each JVM with the commands above.

*Sources: Oracle Critical Security Patch Update, Red Hat bulletin RHSB-2026-018, Google Cloud security bulletins, NVD, the Ubuntu, SUSE and Alpine security feeds, Qualys, Tenable, Rapid7, Semgrep (checked on 18 November 2026)*

---

## PROTECTION ROADMAP

### For non-technical executives

#### HOUR 1: Emergency assessment

**Immediate actions checklist:**

- [ ] Get IT, the engineering leads and your hosting, cloud and software providers on one call
- [ ] Ask: "Which of our systems run Java, and which of them can be reached from the internet?" Include anything a vendor, an outside team or a hosting company runs for you, and products that carry their own Java inside them (Jira, Confluence, Jenkins, Keycloak and Elasticsearch are examples). Updating the server's Java does not change those
- [ ] Ask for these facts per system: its Java build, whether it runs on the newer Intel Xeon or AMD EPYC chips the bug needs, and whether the vulnerable path is switched on (IT runs the Quick 5-minute assessment). A system on older Intel chips or on ARM isn't exposed to this bug today. A patched runtime does nothing until the system restarts
- [ ] Put the internet-facing identity and single sign-on servers, the build and artifact servers, and Jira and Confluence at the top of the list
- [ ] Ask every vendor whose product carries its own Java, in writing, which Java build it runs and when its fix ships. As of 18 November we found no statement from Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache (Tomcat, Kafka, Solr), Cisco, IBM or SAP, nor from AWS Lambda, Elastic Beanstalk, Azure App Service or Azure Functions (Microsoft), and Ping Identity and Broadcom could not be checked. Don't wait for them to write to you
- [ ] Flag every system that runs a Java build from a vendor with no fixed build yet (at the cut-off: Eclipse Temurin, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux), and every system on a retired Java line (18 to 20, 22 to 24, 26), which will get no fix
- [ ] Approve emergency maintenance, including restarts during business hours and taking a service offline if it comes to that
- [ ] Tell legal, compliance and your cyber insurer that you're responding

**Decision points:**

- Everything fixed and restarted, or not exposed (older chips, ARM, standard Java 8, Java 11 or Java 17.0.0 to 17.0.5, or the vulnerable path switched off): document it and move to WEEK 1: Verification and assessment.
- Internet-facing systems on exposed hardware where the vendor has shipped a fix: approve patching and a restart today. Identity, build and artifact servers go first.
- Systems with no fix available yet: approve the stopgap in For technical teams, which is a setting that turns off the vulnerable code until the fix arrives (Red Hat's preferred option, and Calif recommends it too), and ask the vendor in writing for a date. It needs a restart. Base64-heavy work such as tokens and SAML may slow down, and nobody has published numbers, so test one system first (our reading).
- Systems on older chips or on ARM: not exposed to this bug today. Schedule the update in the normal window, because workloads move between machine types.

---

#### DAY 1: Emergency response

**Executive decision checklist:**

- [ ] Approve maintenance windows. Every patched Java system has to restart, and container setups have to be rebuilt and redeployed, so plan for short interruptions
- [ ] Decide what to do about systems that can't take the fix today. That means platforms with no fixed build yet, products that carry their own Java, and retired Java lines:
    - [ ] **Option A:** Move the service to a Java build that already has the fix (Oracle, Amazon Corretto, Azul Zulu and SAP SapMachine have shipped them), or to a supported release line (21.0.13.1, 25.0.5.1 or 27.0.1.1) if it is on a retired one. For a product with its own Java, use the vendor's update or a supported swap of the runtime (safest)
    - [ ] **Option B:** Take internet-facing services offline, or isolate them from public networks, until the fix arrives (the Canadian Centre's advice)
    - [ ] **Option C:** Apply the stopgap setting and restart (Red Hat: it "disables the hardware-accelerated Base64 implementation only"). The runtime stays unpatched, so it is a stopgap
    - [ ] **Option D:** Extra layers only: isolate the service, restrict and validate Base64 input at the application boundary (CISA), and use a WAF. This leaves the most risk behind: size limits alone won't stop it, AWS's Java4Shell rules log and don't block until the action is changed, and no network control recovers data already read from memory
- [ ] Agree the secrets rule now (our reading). If an internet-facing identity, single sign-on, CI or artifact server ran an affected build on exposed hardware with the defaults on, and was neither patched nor flagged after 21:00 UTC on 17 November 2026 (the coordinated release, by Calif's account, with a commercial exploit two hours later), plan to rotate its signing keys and stored credentials right after patching, and to invalidate the sessions and tokens it issued. Users may be signed out. Patching closes the hole but doesn't undo a memory read, and the memory read can leave no crash
- [ ] Communication plan:
    - [ ] Brief the board if you're publicly traded
    - [ ] Prepare a customer notice in case a service has to go offline
    - [ ] Tell your cyber insurer
    - [ ] Ask legal for a compliance read
- [ ] Resources:
    - [ ] Approve overtime or outside help if the team is stretched
    - [ ] Call in your incident response retainer if you have one

---

#### WEEK 1: Verification and assessment

**Follow-up checklist:**

- [ ] Confirm, with evidence, that every internet-facing Java system on exposed hardware runs a fixed build or has the stopgap set, and has restarted. Evidence means output from the system (the live version, and the flags where you used the stopgap), not a package list or a ticket
- [ ] Review logs back to at least 9 September 2026, when the problem and the fix approach first appeared in a public OpenJDK pull request. No source we checked confirms attacks in the wild, but clean logs prove little: no indicators of compromise have been published beyond scanner traffic, and Prophet Security warns that "a quiet application log does not rule out an attempt". A failed attempt can look like a crashed JVM or an ordinary rejected request
- [ ] Re-check vendor and platform advisories. At the cut-off Red Hat's bulletin status was "Ongoing", Eclipse Temurin's release status showed testing in progress, and IBM Semeru's status was unclear (Red Hat's VEX file lists it as known affected on RHEL 10, and IBM has made no statement). Products that bundle Temurin, such as the official Jenkins, Tomcat and Kafka images, wait for Temurin
- [ ] Ask your scanner vendor how it judges Java builds, CPUs and flags. A version scanner can't see the CPU or the JVM flags, so a clean scan proves little and a flagged system may not be exposed
- [ ] Rotate secrets on the first-tier systems (right after patching, as agreed on DAY 1) and on any other affected service whose logs show warning signs since 9 September 2026. That covers database passwords, API keys, cloud credentials, OAuth and OIDC client secrets, JWT and SAML signing keys, TLS private keys in Java keystores, and secrets in configuration or the environment
- [ ] Hold a post-incident review with the technical teams
- [ ] Compliance:
    - [ ] Check notification duties if you found any sign of compromise
    - [ ] Keep timestamped records of everything you did
    - [ ] Preserve evidence before restarting a system you suspect. Crash logs and memory dumps hold secrets, so treat them as sensitive
    - [ ] Get legal advice before you conclude "no breach"
    - [ ] Check the patch deadlines that apply to you. PCI DSS v4.0.1 requirement 6.3.3 expects patches for critical vulnerabilities, as ranked by your own process, to be "installed within one month of release" (secondary sources, which disagree on whether v4.0.1 still covers high-severity patches). Our reading: about 17 December 2026 for the builds released on 17 November, and the day each product vendor ships for products that bundle Java. With CISA's SSVC values for this CVE, BOD 26-04 gives US federal agencies 14 days for a publicly exposed asset while the CVE is not in KEV, and 3 days plus forensic triage once it is (calendar days)

---

#### MONTH 1: Strategic planning

**Lasting improvements:**

- [ ] Keep a live inventory of every Java runtime, including those bundled in products, container images and appliances, with its build, who supplies it, what hardware it runs on, which JVM flags it starts with and what sits in front of it. CISA: runtimes "may not appear as separate entries in software inventories"
- [ ] Retire golden images, VM templates and autoscaling launch configurations that still carry an affected runtime, and rebuild container images on fixed bases
- [ ] Move retired Java lines (18 to 20, 22 to 24, 26) to a supported line
- [ ] Treat hardware as part of the risk. Know which node pools and machine types have AVX-512 VBMI, and decide on purpose where workloads may land: the same image can be exposed on one node and safe on the next (our reading)
- [ ] Subscribe to the security advisories, not only the release announcements. This fix sat in public repositories for weeks before the release, first in a pull request on 9 September and then in the Java 27 update repository from 14 October under a title that doesn't mention security. Add your Java vendor's and distribution's feeds, and your product vendors' bulletins
- [ ] Agree a patch and restart policy for runtimes: how fast a runtime fix reaches production, who may approve an emergency restart, and when the maintenance windows are. A Java fix does nothing until each JVM restarts, and a product with its own Java waits for its vendor
- [ ] Add detection for JVM crashes, unexplained service restarts and Java processes that start shells or download tools (DETECTION & FORENSICS says how)
- [ ] Check what your scanner sees: does it know the CPU, the JVM flags and bundled runtimes, or only version numbers? NVD has no product data for this CVE, so tools that read NVD alone miss it
- [ ] Put the coming dates in the calendar: 30 November 2026, when Google's CPU-feature masking on managed Java runtimes ends. 15 December 2026, Oracle's next Critical Security Patch Update. 19 January 2027, Oracle's next quarterly Critical Patch Update, after which Oracle's 17.0.21.1 notes say it is not recommended to use that build
- [ ] Review hosting and vendor contracts for patch timelines and notification duties
- [ ] Run a tabletop exercise based on this incident

*Sources: Oracle Critical Security Patch Update and release notes, the OpenJDK advisory and update repositories, Red Hat bulletin RHSB-2026-018, Canadian Centre for Cyber Security, CISA alert and BOD 26-04, Google Cloud security bulletins, Prophet Security, PCI DSS v4.0.1 secondary sources, vendor and cloud provider pages (checked on 18 November 2026)*

---
### For technical teams

#### IMMEDIATE ACTIONS (Hour 1-2)

**Phase 1: Assessment and inventory**

**Checklist:**

- [ ] Find every JVM you run: servers, virtual machines, cloud instances, container images and running containers, Kubernetes node pools, build agents and developer laptops. Add the VM images, golden images and autoscaling launch configurations that new machines start from
- [ ] Find every product that carries its own Java (Jira, Confluence, Elasticsearch, and the Jenkins and Keycloak images, among others). Patching the system Java does not change them. CISA's advice: "Review your software inventory for JDKs and Java runtimes, including those bundled with third-party applications or included in container images and appliances. Note: JDKs and Java runtimes may not appear as separate entries in software inventories."
- [ ] Record the full version string and who supplies the build (Oracle, Amazon Corretto, Eclipse Temurin, Azul Zulu, a distro or a product vendor). Judge each build by its own vendor's list, because vendors number builds differently
- [ ] Record whether the CPU has AVX-512 VBMI, checked on the host or inside the VM guest, and whether the JVM's flags leave the vulnerable path on
- [ ] Record whether the application passes Base64 that an outsider controls to the basic or URL-safe decoder (`Base64.getDecoder()` and `Base64.getUrlDecoder()`). The MIME decoder skips the vulnerable path. Red Hat names typical carriers: HTTP Basic credentials, SAML artifacts, CSRF tokens and MIME encoded words
- [ ] Record whether a WAF or reverse proxy sits in front, and which rules it runs. It is a layer, not a fix
- [ ] Put internet-facing JVMs on VBMI hardware first, starting with identity and single sign-on servers, CI and artifact servers, Jira and Confluence. Then internal services on that hardware, and Java programs that open TLS connections to servers you don't control. Patch JVMs on ARM64 and on x86-64 without VBMI in your normal window, because workloads move between machine types

**Commands for assessment:**

```bash
# Running JVMs on this host (run as root to see every user's JVMs). JVMs inside containers don't show here: run it inside each container
jcmd -l
# The live version of one JVM (run as the JVM's user or root)
jcmd <pid> VM.version
# Is the vulnerable path switched on in that JVM?
jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
# Does this machine, or this VM guest, have AVX-512 VBMI? Prints avx512vbmi if it does
grep -o -w avx512vbmi /proc/cpuinfo | head -1
# Kubernetes with Node Feature Discovery: the nodes that have AVX-512 VBMI
kubectl get nodes -l feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI=true
# Java runtimes on disk, including bundled ones (run as root). Compare the full version string
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name release -exec grep -H -E '^(IMPLEMENTOR|JAVA_RUNTIME_VERSION|JAVA_VERSION)=' {} + 2>/dev/null
# Distribution packages (they don't show bundled or tarball runtimes)
dpkg -l 'openjdk-*'
rpm -qa 'java-*openjdk*'
```

Variants for platforms the block above misses:

```bash
# Amazon Linux: Corretto packages have their own names, so the pattern above misses them
rpm -qa 'java-*amazon-corretto*'
# Alpine: installed Java packages with versions
apk info -v | grep -i openjdk
# macOS with Homebrew: installed Java formulae with versions
brew list --versions | grep openjdk
# The first java on the PATH, for laptops and scripts. A service can run a different one
java -version
# Which java binary a live JVM runs from, to tell the system Java from a bundled one (Linux; run as the JVM's user or root)
readlink -f /proc/<pid>/exe
```

How to read the output:

- `jcmd -l` lists only the JVMs the current user can see, and JVMs inside containers don't show. Run it as root on the host, and again inside each container.
- Compare the `VM.version` string with the fixed builds in Option A below. The fix is the .1 build (17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1, or your vendor's number for it). The October respins ending in .0.2 and .0.3 look newer and are the last vulnerable builds.
- Exposed means UseAVX is 3 and UseBASE64Intrinsics is true, on a VBMI CPU, with C2 running. Not exposed means UseBASE64Intrinsics is false, or UseAVX is 2 or lower, or TieredStopAtLevel is 1.
- No `avx512vbmi` line means the machine or guest has no VBMI. Output from `lscpu` that contains "avx512" is not enough, because Skylake-SP and Cascade Lake print AVX-512 flags without VBMI (the Canadian Centre's `lscpu | grep avx512` over-reports).
- Hardware with VBMI: Intel Xeon from Ice Lake-SP on, AMD from Zen 4 on (EPYC 9004 and 9005, Ryzen 7000 and later), and Intel client Ice Lake, Tiger Lake and Rocket Lake, so some developer laptops and desktops are exposed. ARM64 (AWS Graviton, Ampere), Skylake-SP, Cascade Lake, Cooper Lake and AMD Zen 3 and older do not have it.
- In a virtual machine, HotSpot turns AVX-512 on only when the CPU reports it and the operating system has enabled its register state. A hypervisor that masks VBMI removes the path, so run the CPU check inside each guest.
- A release file describes the runtime on disk, and the package lists show system packages only. After an in-place upgrade a running JVM still runs the old code, so trust `jcmd <pid> VM.version` for live processes. Bundled and tarball runtimes don't appear in package lists.

For bigger estates, run the checks through your configuration management, remote execution or EDR tooling and collect the output into one table keyed by host: version string, CPU check, flags and runtime path. A package list says what is installed, and the fix counts only in the JVM that is running.

Don't test your hosts with proof-of-concept code, checkers or self-tests from public repositories. At 07:46 UTC on 18 November, 25 repositories mentioned the CVE. None is verified, and running unknown code is a common way to get compromised. Pentestit's advice: "Read any script before you run it."

*Sources: CISA alert, Red Hat bulletin RHSB-2026-018, Canadian Centre for Cyber Security alert AL26-029, Oracle Critical Security Patch Update, HotSpot source for the CPU and flag checks, Pentestit, GitHub repository search (state on 18 November 2026, 08:00 UTC)*

**Document your findings:**

```
Host / image / node pool / product / laptop:
Platform and release:
Role and exposure [internet-facing / internal only / opens TLS connections to servers we don't control]:
Java vendor and full version string (jcmd <pid> VM.version):
Where the runtime comes from [system package / bundled with a product / container image / tarball / managed platform]:
Affected build [yes / no / vendor has not said]:
CPU has AVX-512 VBMI [yes / no / varies by node], and where it was checked [host / guest]:
Flags: UseAVX, UseBASE64Intrinsics, TieredStopAtLevel, TieredCompilation (jcmd <pid> VM.flags -all):
WAF or proxy in front, and its mode [none / AWS WAF Count / AWS WAF with a blocking action / other]:
Fixed build for this platform [yes / no / vendor has no fix yet]:
Stopgap [-XX:-UseBASE64Intrinsics / -XX:UseAVX=2 / none], where it is set, date and who:
Restarted after the upgrade [yes / no, time]:
Status [fixed / exposed / not exposed on this hardware / no fix yet]:
```

---

**Phase 2: Emergency patching**

**Pre-patch checklist:**

- [ ] Snapshot or back up the server or image, configuration included
- [ ] Note the current version string (`jcmd <pid> VM.version`) and the JVM's launch options, for rollback
- [ ] Write down any stopgap flag you applied, and where you set it, so you can remove it on purpose later
- [ ] Tell stakeholders about the maintenance window. A restart cuts requests that are in flight, so plan the order: internet-facing services on VBMI hardware first, starting with identity and single sign-on servers, CI and artifact servers, Jira and Confluence
- [ ] Have a rollback plan ready, with a time limit. A rollback puts the vulnerable build back
- [ ] For a JVM you suspect, capture state before you restart it, because a restart destroys the memory of the JVM. DETECTION & FORENSICS says what to look for, and ADVANCED FORENSICS says what to preserve

**Patching commands:**

Install the fixed build for your vendor, restart every JVM that used the old runtime, and rebuild container images. The restart is not optional: a build on disk doesn't fix a JVM that is still running. Patch in the order from Phase 1.

```bash
# Amazon Linux 2023 (run as root). Use the package names you have installed
dnf update java-17-amazon-corretto --releasever 2023.12.20261117
# Amazon Linux 2 (run as root)
yum update --advisory ALAS2-2026-4123
# Arch Linux (run as root)
pacman -Syu
# Homebrew, for each formula you use
brew update && brew upgrade openjdk@21
```

```dockerfile
# Docker: rebuild your image on a fixed base, then redeploy. Pin the digest after you have checked it
FROM amazoncorretto:21
```

```bash
# After the restart, confirm each live JVM runs the fixed build (run as the JVM's user or root)
jcmd <pid> VM.version
# Container images: the version inside the image, not the tag name
docker exec <container> java -version
```

These commands cover Amazon Linux 2023, Amazon Linux 2, Arch Linux, Homebrew and Docker. Oracle, Azul and SAP builds come from their download pages and repositories. Debian, Ubuntu, Red Hat, SUSE, Alpine and Temurin users have no fixed package yet: apply the stopgap below now and update when the advisory lands. Products with their own Java (Jira, Confluence, Elasticsearch and others) need the product vendor's update, or a supported swap of the runtime, because updating the system Java does not change them. Retire golden images, VM templates and autoscaling launch configurations that still carry an affected runtime. Option A, Option B and Option C say what each platform had on 18 November 2026.

**Option A: Builds that are fixed (the fix is the vendor build plus a restart)**

- OpenJDK upstream: tags jdk-17.0.21.1+2, jdk-21.0.13.1+2, jdk-25.0.5.1+2 and jdk-27.0.1.1+4. Rebuild anything you compile yourself from them.
- Oracle: Java SE 17.0.21.1+4, 21.0.13.1+4, 25.0.5.1+4 and 27.0.1.1+4, all released 17 November 2026. Java SE 8u513-perf (1.8.0_513-perf-b4) fixes the Java 8 Performance Pack. Oracle GraalVM for JDK 17.0.21.1, 21.0.13.1 and 25.0.5.1, and GraalVM Enterprise Edition 21.3.20.1. Oracle's 17.0.21.1 notes say it is not recommended to use that build after the quarterly Critical Patch Update of 19 January 2027.
- Amazon Corretto: 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2 and 27.0.1.1.4 (GitHub releases, 17 November, 19:49 to 20:06 UTC). Amazon Linux 2: ALAS2-2026-4123 (java-17-amazon-corretto 17.0.21.1.2). Amazon Linux 2023: ALAS2023-2026-3478 to 3481 (java-17, -21, -25 and -27-amazon-corretto). Amazon Linux 2027 preview: ALAS2027-2026-371 to 374. All 17 November.
- Azul Zulu: 17.70.201, 21.54.201, 25.38.201 and 27.30.201, and the security-only stream 17.69.204, 21.53.202 and 25.37.202 (17 November).
- SAP SapMachine: 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1 (17 November).
- Arch Linux: jdk17-openjdk 17.0.21.1.u2-1, jdk21-openjdk 21.0.13.1.u2-1, jdk25-openjdk 25.0.5.1.u2-1 and jdk-openjdk 27.0.1.1.u4-1 (built 17 November).
- Homebrew: openjdk 27.0.1.1, openjdk@17 17.0.21.1, openjdk@21 21.0.13.1 and openjdk@25 25.0.5.1.
- Container images, buildpacks and managed platforms (Docker, Paketo, Heroku, Google) are in Option C.

**Option B: Vendors with no fix, or no confirmed fix, yet**

- Eclipse Temurin and the eclipse-temurin Docker images: the newest GA is still 17.0.21+9, 21.0.13+9 and 25.0.5+8, and Adoptium's release-status issue 326 shows testing in progress. This also holds back images built on Temurin, such as the official Jenkins, Tomcat and Kafka images.
- Red Hat: no errata. VEX revision 3 lists 138 products as known affected: RHEL 8 (java-17 and java-21-openjdk), RHEL 9 (java-17, -21 and -25-openjdk), RHEL 10 (java-21 and java-25-openjdk, plus java-21-ibm-semeru-certified-jdk), and Red Hat build of OpenJDK 17, 21 and 25. Hardened Images (hi/openjdk) is "Fix deferred". The bulletin's status is "Ongoing".
- Microsoft Build of OpenJDK: the newest builds are 17.0.21.0.2, 21.0.13.0.2 and 25.0.5.0.2.
- BellSoft Liberica: the newest builds are the affected .0.3 releases.
- Debian: openjdk-17, -21, -25 and -27 are unfixed in bookworm, trixie, forky and sid.
- Ubuntu: no CVE entry yet. SUSE: no CVE page yet. Alpine: edge still ships the .0.3 builds.
- GraalVM Community: the newest release (3 November) is built on the affected 25.0.5.0.3.
- Oracle Linux, Rocky Linux and AlmaLinux: no advisory yet. Fedora: we couldn't check it.
- IBM Semeru (OpenJ9) is contested. Red Hat's VEX file lists java-21-ibm-semeru-certified-jdk on RHEL 10 as known affected, while IBM has made no statement and OpenJ9 issue 25216 is open with no reply.
- No statement found: AWS Lambda, AWS Elastic Beanstalk, Azure App Service, Azure Functions (Microsoft), and the product vendors Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache (Tomcat, Kafka, Solr), Cisco, IBM and SAP. Ping Identity and Broadcom could not be checked.

While you wait for a fix, in order of preference:

1. Where a workload can move, move it to a platform from Option A that already has a fixed build.
2. Apply the stopgap flag below, then restart.
3. Isolate the service from public networks where it allows it, and limit unauthenticated access. This is a layer, not a fix.
4. Check the vendor page every day, and patch the day a fixed build appears.

Treat every measure below as interim. Several vendors had not shipped a fix at the cut-off, so check your vendor's or distro's advisory again before you rely on a "no fix yet".

**Option C: Containers, node pools, managed platforms and golden images**

- Docker, Corretto: Amazon rebuilt the amazoncorretto images on 17 November (23:50 to 23:56 UTC) under their old tag names, for example 17.0.21-alpine3.24. A tag name doesn't prove a fixed image, and a container keeps the runtime it started with until you replace it. Check `java -version` inside the image (the `docker exec` command in the patching block), or pin the digest after you have checked it. Rebuild your own images on a fixed base and redeploy.
- Docker, Temurin and images built on it: the eclipse-temurin images wait for Adoptium (Option B), and that holds back the official Jenkins, Tomcat and Kafka images. Apply the stopgap to those containers now, and rebuild when the fixed images appear. The official Jenkins image carries its Temurin runtime at /opt/java/openjdk and gets the fix only after Adoptium publishes and Jenkins rebuilds. The official Keycloak image uses the UBI 9 java-21-openjdk-headless package, so its fix follows Red Hat's errata, and Red Hat has published none.
- Paketo: the azul-zulu buildpack has the fix (11.8.3 and 11.8.4, 18 November). Rebuild images built with it.
- Kubernetes node pools with mixed CPUs: the same image can be exposed on one node and safe on the next, because the path depends on the CPU each node reports (a hypervisor that masks VBMI removes it). Treat any node pool that contains a VBMI node as exposed (our reading). Where you run Node Feature Discovery, the `kubectl get nodes` label query in Phase 1 lists the VBMI nodes. Otherwise run the CPU check inside each guest.
- Google: as an interim platform safeguard through 30 November 2026, Google says it has masked AVX-512 VBMI for managed Java 17, 21 and 25 runtimes on the App Engine standard environment and the Cloud Run second generation execution environment (including 2nd gen Cloud Run functions). It "does not cover the Cloud Run first generation execution environment, Cloud Functions (1st gen), App Engine flexible environment, Cloud Run jobs and worker pools, custom containers, or deployments without automatic base image updates". The safeguard ends on 30 November 2026, so patch before then. Google recommends -XX:UseAVX=2, in the mixed-fleet form shown in the stopgap block.
- Heroku: the defaults moved to 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, effective 18 November. Confirm the version your running app reports.
- Azure Functions: the Java worker starts the JVM with -XX:+TieredCompilation -XX:TieredStopAtLevel=1, so only C1 runs and the default configuration doesn't reach the vulnerable path. Options that re-enable C2 bring it back, for example -XX:TieredStopAtLevel=4 or -XX:-TieredCompilation set in JAVA_OPTS, languageWorkers__java__arguments or _JAVA_OPTIONS. The worker issue checked whether the intrinsic was used and did not test memory corruption. Microsoft has published no advisory. Check your app settings for those options.
- AWS Lambda and Elastic Beanstalk: we found no statement.
- Retired Java lines: 18 to 20, 22 to 24 and 26 get no fix. Amazon marks its 22, 23, 24 and 26 packages "No Fix Planned". Move them to 21.0.13.1, 25.0.5.1 or 27.0.1.1.
- Java 8 and 11: not affected by this CVE, because standard Java 8 and Java 11 lack the vulnerable code. Oracle's November release has 11 Java SE fixes, and CVE-2026-114946 (4.8, Compiler) is a separate flaw that covers every line including 8 and 11, so these hosts still need the November updates. Oracle's baselines are 1.8.0_513-b04 and 11.0.33.1+4.
- Golden images: update or rebuild the golden image, the VM template and every autoscaling launch configuration that points at it. A new instance from an old image comes up on the old runtime.

Products that carry their own Java (updating the system Java does not fix them):

| Product | Runtime it carries | Where the fix comes from |
| --- | --- | --- |
| Jira | The Windows and Linux installers bundle Eclipse Temurin (11.3.10 and 11.3.11 bundle 21.0.10_7). A tar.gz install uses your own Java | The product vendor's update, or your own Java on a tar.gz install |
| Confluence | The installer bundles Temurin (11.0.1 bundles 25.0.5.8, and 10.2.20 bundles 21.0.13.9) | The product vendor's update |
| Jenkins | The official jenkins/jenkins image carries a Temurin runtime at /opt/java/openjdk | Adoptium publishes, then Jenkins rebuilds the image |
| Keycloak | The official image uses the UBI 9 java-21-openjdk-headless package | Red Hat's errata, which are not published yet |
| Elasticsearch | Its own bundled JDK by default. The development branch pins 27.0.1.0.3, an affected build | The product vendor's update, or a supported swap of the runtime |
| PingFederate | The zip install uses a Java you install | The Java you install |
| Tomcat and Kafka | The system Java on tarball installs. Their official container images are built on eclipse-temurin | Your own Java, or Adoptium and then a rebuilt image |
| JFrog Artifactory | Not verified, because its documentation was unreachable | Not verified |

*Sources: Oracle Critical Security Patch Update and release notes, OpenJDK advisory and tags, Red Hat bulletin RHSB-2026-018 and VEX file, Amazon Linux Security Center and Corretto releases, Azul, SAP SapMachine, Arch and Homebrew package pages, Adoptium release-status issue, Debian security tracker, OpenJ9 issue tracker, Heroku changelog, Google Cloud support bulletins, Azure Functions Java worker issue and documentation, Paketo, Docker Hub and docker-library, Atlassian, Elastic, Jenkins, Keycloak, Ping Identity, Apache Tomcat and Kafka documentation (state on 18 November 2026, 08:00 UTC)*

**Restart into the fixed build (the step people skip)**

Installing the build is half the job. A running JVM keeps the old code in memory until it restarts, and it stays exposed the whole time. A release file or a package list describes what is on disk, not what runs. Restart every JVM that used the old runtime, and check `jcmd <pid> VM.version` on the live process afterwards. In a container, rebuild and replace it, because restarting the old container starts the same old image. Restart commands depend on how each service runs (service manager, orchestrator rollout or redeploy), so this document gives none: use the process you already use for that service.

**Can't patch today? Apply the stopgap.** This is a bridge, not a fix. DEFENSE-IN-DEPTH MEASURES has the full list.

- Preferred: start each affected JVM with -XX:-UseBASE64Intrinsics, then restart. Red Hat: it "disables the hardware-accelerated Base64 implementation only. This is the preferred option, as it removes the vulnerable code path while leaving other AVX-512 optimizations in place." Calif recommends it too. It is a regular product flag in Java 11 and later on both x86-64 and ARM64. OpenJDK 8 does not know it and would refuse to start, so don't set it where a Java 8 JVM reads it. No source says whether Oracle's Java 8 Performance Pack accepts it.
- Alternative: -XX:UseAVX=2 turns off all AVX-512 code in the JVM. x86-64 only: an ARM64 JVM won't start with it. The Canadian Centre and Google recommend it. Google's form for mixed fleets adds -XX:+IgnoreUnrecognizedVMOptions, set in JDK_JAVA_OPTIONS, which only the java launcher reads.
- Both need a restart. Base64-heavy work (tokens, SAML) may slow down, and nobody has published numbers, so test one node first (our reading).
- Where the flag goes decides whether it works. JAVA_TOOL_OPTIONS is read by the JVM itself (it prints "Picked up JAVA_TOOL_OPTIONS") and reaches custom launchers. HotSpot skips it only when the process has special privileges, such as a setuid launch. JDK_JAVA_OPTIONS is read only by the java launcher. Products with their own launchers need the flag in their own configuration. Elasticsearch strips both variables, and Keycloak's JAVA_OPTS replaces its defaults.
- Remove the flag once the fixed runtime is confirmed (Red Hat, Google).

```bash
# Preferred stopgap through the JVM's own variable. Add it to the service's environment, keeping any value already there, then restart the service
JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
# Google's form for fleets that mix x86-64 and ARM64 (read by the java launcher only)
JDK_JAVA_OPTIONS="-XX:+IgnoreUnrecognizedVMOptions -XX:UseAVX=2"
```

Product settings (add the flag to what is already there, then restart):

```bash
# Jira: <jira-install>/bin/setenv.sh
JVM_SUPPORT_RECOMMENDED_ARGS="-XX:-UseBASE64Intrinsics"
# Confluence: <installation-directory>/bin/setenv.sh, keeping ${CATALINA_OPTS} in place
CATALINA_OPTS="-XX:-UseBASE64Intrinsics ${CATALINA_OPTS}"
# Keycloak: use JAVA_OPTS_APPEND, never JAVA_OPTS
JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics"
# Jenkins container
JENKINS_JAVA_OPTS="-XX:-UseBASE64Intrinsics"
# Tomcat: $CATALINA_BASE/bin/setenv.sh
CATALINA_OPTS="$CATALINA_OPTS -XX:-UseBASE64Intrinsics"
# Kafka
KAFKA_OPTS="-XX:-UseBASE64Intrinsics"
```

```text
# Elasticsearch: a file such as config/jvm.options.d/java4shell.options containing this one line
-XX:-UseBASE64Intrinsics
# PingFederate: add this line to pingfederate/bin/jvm-memory.options
-XX:-UseBASE64Intrinsics
```

Notes on the product settings:

- Jira: for the Docker image, set the JVM_SUPPORT_RECOMMENDED_ARGS variable.
- Keycloak: setting JAVA_OPTS replaces all of Keycloak's defaults ("JAVA_OPTS already set in environment; overriding default settings"), so add the flag with JAVA_OPTS_APPEND.
- Jenkins: JENKINS_JAVA_OPTS (or JAVA_OPTS) in the container. Package installs use a systemd override.
- Elasticsearch: its launcher strips JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS, so use the options file. On Debian and RPM installs the folder is /etc/elasticsearch/jvm.options.d/. For Docker, bind mount the file into /usr/share/elasticsearch/config/jvm.options.d/.
- Tomcat and Kafka: their official container images are built on eclipse-temurin, which is still waiting for a fix, so these are the lines to use on those images.

```bash
# After the restart, confirm the running JVM picked it up (run as the JVM's user or root)
jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
```

- Read the output: exposed means UseAVX is 3 and UseBASE64Intrinsics is true, on a VBMI CPU, with C2 running. Not exposed means UseBASE64Intrinsics is false, or UseAVX is 2 or lower, or TieredStopAtLevel is 1.

**Network and WAF controls while you wait (a layer, not a fix)**

- The Canadian Centre: "consider isolating internet-facing applications from public networks until a fix can be applied." CISA: "restricting and validating Base64 input at the application boundary, enforcing input-size limits, and limiting unauthenticated access." Size limits alone won't stop it, because the malformed input that triggers it is short (our reading of Endor Labs' description of the trigger).
- AWS WAF: managed rule group Known Bad Inputs version 1.28 adds the Java4Shell_BODY, Java4Shell_QUERYARGUMENTS and Java4Shell_HEADER rules. AWS says: "The new rules in these versions use the Count action." They log, not block, until you change the action.
- Cloudflare's WAF changelog had no Java4Shell entry (newest item 12 November), so there is nothing to switch on there.
- WAF inspection limits, per IONIX: "Cloudflare inspects only the first 128 KB of a body"; "AWS WAF inspects only the first 8 KB of headers, cookies and body"; Akamai Property Manager rules don't cover the request body.
- Calif notes that nginx request buffering frustrates some of its exploit chains, but "Request buffering is not a general mitigation".
- No network control recovers data already read from memory. This document makes no claim that any WAF or proxy blocks the bug, so treat each one as a layer on top of the patch or the flag.

**Verification:**

```bash
# When did each JVM start? It must have started after the upgrade
ps -eo user,pid,ppid,lstart,args | grep '[j]ava'
```

- `jcmd <pid> VM.version` must show the fixed build from Option A. Compare it with your vendor's list, not with the upstream number alone (the version traps are under DEFENSE-IN-DEPTH MEASURES).
- Containers: confirm the running container was created from the rebuilt image, and run `docker exec <container> java -version` in it.
- A release file describes the runtime on disk. Compare each JVM's start time with the time of the upgrade, and restart it if it started earlier. The `readlink` command from Phase 1 shows which java binary the process runs from.
- If you applied the stopgap, run the `VM.flags` check from the stopgap block and read the output as described there.

**Post-patch checklist:**

- [ ] Every patched JVM shows the fixed build in `jcmd <pid> VM.version`, and started after the upgrade
- [ ] Products with their own Java report a fixed runtime, not only the system Java
- [ ] The services work after the restart: listeners are up, health checks pass and dependent systems reconnect
- [ ] Decide on purpose what stays of the stopgap. A patch does not remove a flag you set, and the flag keeps hardware-accelerated Base64 off. Remove it once the fixed runtime is confirmed (Red Hat, Google)
- [ ] Rebuild images, VM templates and launch configurations so that new machines don't come back on the old build
- [ ] If a scanner still flags a patched host, check the version traps before you open a ticket: vendor numbering, a bundled runtime, or a JVM that started before the upgrade
- [ ] Keep the version output and the process start times as evidence
- [ ] Update your asset inventory, bundled runtimes included, and record the restart time
- [ ] On JVMs still waiting for a fix, keep the stopgap in place, check the vendor page every day and watch for `hs_err` crash logs. DETECTION & FORENSICS says which signals matter
- [ ] Rotate secrets by the tiers under ADVANCED FORENSICS, after patching

*Sources: Red Hat bulletin RHSB-2026-018, Calif, Canadian Centre for Cyber Security alert AL26-029, CISA alert, Google Cloud support bulletins, HotSpot source (flag definitions), AWS WAF managed rules changelog, Cloudflare WAF changelog, IONIX, Qualys, Endor Labs, Atlassian, Elastic, Jenkins, Keycloak, Ping Identity, Apache Tomcat and Kafka documentation (state on 18 November 2026, 08:00 UTC)*

---

#### DETECTION & FORENSICS (Day 2-3)

None of the sources we relied on lists indicators of compromise such as file hashes, address lists or request signatures. GreyNoise tags Java4Shell traffic (from 01:18 UTC on 18 November). At 07:18 UTC its tracker showed 3 IPs, 53 requests and 0 successful intrusions, with "Block candidates (0)". We don't list the addresses, and the tracker is linked under ADDITIONAL RESOURCES. What exists is the evidence a crashed or abused JVM leaves: crash logs, swallowed exceptions, odd responses, commands started by Java and new outbound connections, plus one crash signature from Endor Labs that no JDK vendor has confirmed. We have no source that says what a successful attempt leaves in the logs, so a clean result proves little, and the memory read can be quiet (our reading).

Plan for the worse case, which is code execution. No exploitation is confirmed at the cut-off (the review window under ADVANCED FORENSICS gives the dates), so most of this section is about finding exposed JVMs and spotting attempts.

Inventory comes first, because a signal from a JVM you can't place can't be read. Every command here only reads, except the two memory capture tools named under "Preserving evidence before a restart", which change the system. Commands marked "run as root" need it.

**Check for signs of attempts and compromise**

**Fleet inventory at scale:**

Ask four questions of every JVM. Which build is running? Does the CPU have AVX-512 VBMI? Do the flags leave the vulnerable path on? Does the application pass Base64 that an outsider controls to the basic or URL-safe decoder? Run the Phase 1 commands through your configuration management, remote execution or EDR tooling and collect the output into one table keyed by host. You answer the fourth question from the application's design and its logs. A search of your own code for the two decoder calls shows where your code does this. No source says whether `decode(ByteBuffer)` or `wrap(InputStream)` reach the vulnerable code.

| What you see | Reading | Next step |
| --- | --- | --- |
| An affected build on an x86-64 CPU with AVX-512 VBMI, with UseAVX 3, UseBASE64Intrinsics true and C2 running | Exposed to this bug where the application decodes Base64 that an outsider controls | Patch and restart, internet-facing first. Apply the stopgap until then |
| An affected build, but UseBASE64Intrinsics is false, UseAVX is 2 or lower, or TieredStopAtLevel is 1 | Not exposed to this bug while that setting holds. A changed launch option or platform default can undo it | Take the fixed build in your normal window |
| An affected build on ARM64, or on x86-64 without VBMI | Not exposed on that hardware today | Patch in your normal window, because workloads move between machine types |
| Java 11, standard Java 8, or Java 17.0.0 to 17.0.5 | Not affected by this CVE. Oracle's Java 8 Performance Pack is a separate case: 8u511b33-perf is affected and 8u513-perf is fixed | Still take the November updates, which fix other flaws |
| A build ending in .0.2 or .0.3 (for example 21.0.13.0.3) | A respin that looks newer than the October release and is one of the last vulnerable builds | The fix is the .1 build |
| A number that doesn't look like 17.0.21.1 (Corretto 17.0.21.1.2, Zulu 17.70.201) | Vendors number builds differently. Some write-ups wrongly cite 17.0.11 and 21.0.3 as fixes | Judge each build by its own vendor's list |
| A fixed runtime on disk, but the JVM started before the upgrade | The fix is on disk and the old code still runs | Restart (see Verification under IMMEDIATE ACTIONS) |
| A fixed system Java, and a product that carries its own | The bundled runtime is a separate copy | Take the product vendor's update, or a supported swap of the runtime |
| A Corretto image tag that looks fixed | Amazon rebuilt the images under their old tag names, so the tag proves nothing | Check `java -version` inside the image, or pin by digest |
| A node pool with at least one VBMI node | Treat the whole pool as exposed (our reading), because the same image can be exposed on one node and safe on the next | Patch, or set the stopgap flag on every workload in the pool |

Two cases the sources leave open:

- IBM Semeru (OpenJ9): Red Hat's VEX file lists java-21-ibm-semeru-certified-jdk on RHEL 10 as known affected, while IBM has made no statement. Treat it as unconfirmed, and check Red Hat's file and IBM's statement again.
- GraalVM Native Image: probably not affected, because native executables don't run HotSpot's C2 compiler (inferred). No vendor has said so.

Containers carry their own Java. A scan of the host doesn't see inside them, so list the running containers with your runtime and run the Phase 1 commands inside each one.

*Sources: Oracle Critical Security Patch Update, OpenJDK advisory, Red Hat bulletin RHSB-2026-018 and VEX file, HotSpot source, OpenJ9 issue tracker, Upwind, Amazon Corretto and Azul release data (state on 18 November 2026, 08:00 UTC)*

**Network and edge signals:**

No indicator exists to match on, and no source says what an attempt looks like on the wire. What exists is a short list of rules, and the coverage table under DEFENSE-IN-DEPTH MEASURES has their state:

- AWS WAF's Known Bad Inputs rules for Java4Shell run in Count mode, so they log matches and block nothing. Treat a match as a lead.
- The Snort community rules match specific carriers: a SAML artifact, a connector authorization header, a Jenkins header and MIME encoded words.
- Fortinet's endpoint signatures name Oracle Java. Its network IPS detection is still under investigation.
- Where a proxy or WAF ends the client's connection, its logs hold the client side, and the origin sees only the proxy. Keep the proxy and WAF logs for the review window.

A quiet sensor says nothing about success or failure. Semgrep: "A WAF rule, a lack of alerts or a lack of crashes does not prove that a runtime is patched or that no attempt occurred."

*Sources: AWS WAF managed rules changelog, Snort community rules, Fortinet Threat Signal 6668, Semgrep (state on 18 November 2026, 08:00 UTC)*

**Host logs, and what clean logs mean:**

| Where it shows | What it looks like | Notes |
| --- | --- | --- |
| JVM crash log | `hs_err_pid<pid>.log`, with the text "A fatal error has been detected by the Java Runtime Environment". Endor Labs' signature: "Repeated hs_err crashes with a SIGSEGV in a garbage-collection copy routine and a compiled Base64$Decoder.decode0 frame, especially clustered by source." | No JDK vendor has confirmed the signature. VulnCheck says "a simple burst of requests reliably brought the service down in our testing", so repeated matching crashes on an exposed JVM need a look. One crash proves nothing, and a successful memory read may leave no crash at all (our reading) |
| Application log | Bursts of `IllegalArgumentException` from `java.util.Base64$Decoder` on endpoints that need no login. Malformed, padded Base64 in Authorization headers, cookies, SAML fields and tokens | Prophet Security: "Many frameworks catch the exception and reject the request without logging it, so a quiet application log does not rule out an attempt." Scanners send Java4Shell-shaped Base64 too (GreyNoise), so one exception means little |
| Responses | Oversized or binary-looking responses from endpoints that echo decoded input | The only sign of the memory read that we know of (our reading). It needs response sizes in your logs |
| Process list | Shells or download tools started by a Java process | Weak on its own where the application runs scripts: build servers start shells legitimately. Strong where it isn't in your baseline |
| Network | New outbound connections from Java processes | Compare with the destinations the service normally talks to (databases, APIs, backends) |
| Restarts | Container restart counts, and unexplained restarts of Java services | A failed attempt can look like a crashed JVM (Prophet Security). Many other things restart a service, so match the times against deploys and crash logs |

```bash
# JVM crash logs written since 9 September 2026, then the ones with the Base64 decoder in them (run as root)
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name 'hs_err_pid*.log' -newermt '2026-09-09' -print 2>/dev/null
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name 'hs_err_pid*.log' -newermt '2026-09-09' -exec grep -l 'Base64\$Decoder' {} + 2>/dev/null
# Every process as a tree, with owner, parent and start time (Linux). Look at what sits under each java process
ps -eo user,pid,ppid,lstart,args --forest
# The unit's journal since the review window opened. Read it for restarts that no deploy explains (run as root). Replace <service> with the unit name
journalctl -u <service> --no-pager --since '2026-09-09'
```

Three caveats apply:

- It shows live processes only. A command that ran and exited leaves nothing for `ps`. Pair it with process-creation logging from your EDR or the audit subsystem, filtered on Java processes as parents.
- Build and CI servers start shells as part of normal work, so baseline a known-good server of the same role first.
- A crash log shows a crash, and a service restart shows a restart. Neither shows what was read from memory.

For outbound connections, use the tools you already have: firewall or flow logs. We give no commands for those, because no source gives a pattern to look for.

A quiet crash log doesn't clear a JVM. The memory read can leave no crash (our reading), and we have no source on what a successful attempt leaves behind. A fixed build closes this bug, and it doesn't tell you what happened before it was running. If logs rotate fast or stay only on the host, the evidence may already be gone, so send them off the host (see Monitoring and alerting under DEFENSE-IN-DEPTH MEASURES).

*Sources: Endor Labs, Prophet Security, VulnCheck, GreyNoise, HotSpot source, Semgrep (state on 18 November 2026, 08:00 UTC)*

**Preserving evidence before a restart:**

A restart destroys the memory of the JVM, and the memory read can leave no crash (our reading). On a JVM you suspect, capture first and restart second. Copy the crash logs and the application, proxy and WAF logs off the host before the restart, because replacing a container or rebuilding a host wipes the local copies. Two tools capture memory, and both change the system:

- `jcmd <pid> GC.heap_dump <file>` forces a full garbage collection unless -all is given, and writes a heap-sized file full of secrets.
- `gcore <pid>` needs ptrace rights (root on hardened hosts).

Treat dumps and crash logs as sensitive. Write them to an evidence volume, encrypt them and limit who can read them. ADVANCED FORENSICS has the full capture order.

*Sources: HotSpot diagnostic command source, Linux kernel Yama ptrace documentation*

**How to read the signals together:**

| What you see | Reading | What to do |
| --- | --- | --- |
| An exposed JVM and nothing else | Exposed, not known to be hit. Clean logs prove little | Patch and restart, or apply the stopgap. Copy the logs off the host first |
| One `hs_err` crash log | Probably another cause, but an attempt can't be ruled out | Note the time, read the application and proxy logs around it, and check whether the JVM is patched or flagged |
| Repeated crash logs with a Base64 decoder frame on an exposed JVM, clustered by source | Matches Endor Labs' signature, which no JDK vendor has confirmed | Treat it as an attempt. Keep the crash and access logs, patch, and run the other checks on this host. Check the rotation tiers |
| Bursts of `IllegalArgumentException` from the Base64 decoder on endpoints that need no login | Probing. Scanners send Java4Shell-shaped Base64 too (GreyNoise), so it is not proof of a hit | Check the build and the flag, and look for crashes at the same times |
| Oversized or binary-looking responses from an endpoint that echoes decoded input | A possible memory read (our reading) | Treat it as an incident. Preserve first, then rotate by the tiers |
| A shell or download tool started by a Java process, and it is not in your baseline | Possible code execution | Incident. Preserve first (see ADVANCED FORENSICS), then rebuild |
| An outbound connection from a Java process to an address you don't know | Possible download, reverse connection, or the client-side case | Incident. Block it at your egress point and keep the flow logs |

**What the JVM could read:**

Calif describes the memory read as "the ability to leak contents from the Java heap, which may hold PII, private keys, other secret keys, and tokens". It is not a separate CVE. What leaks is what the JVM held in memory when it was read, so build your rotation list from what the service held:

- Database passwords, API keys and cloud credentials the service uses
- OAuth and OIDC client secrets, and JWT and SAML signing keys
- TLS private keys loaded from Java keystores
- Secrets in configuration files or the environment
- Personal data, tokens and sessions of the users it served
- Anything else the process could read or reach

**Compromise indicators checklist:**

- [ ] Every internet-facing JVM on an affected build and VBMI hardware runs a fixed build, has the stopgap flag, or has a written reason and a date
- [ ] No `hs_err` crash log with a Base64 decoder frame since 9 September, or each one traced
- [ ] No unexplained bursts of `IllegalArgumentException` from the Base64 decoder on endpoints that need no login
- [ ] No unexplained restarts of Java services or containers
- [ ] No shell or download tool started by a Java process outside your baseline
- [ ] No unexplained outbound connection from a Java process
- [ ] You know which products carry their own Java, and which runtime each one runs
- [ ] No unverified checker or proof-of-concept code was run on a production host

**If ANY indicator turns up:** start incident response. One crash log is weak evidence, and a shell started by a Java process, or a crash followed by a new outbound connection, is not. A clean log doesn't clear a JVM. If an exposed, unpatched JVM shows any indicator, treat it as compromised until you can show otherwise. Capture state before you restart it (see ADVANCED FORENSICS), rebuild on a fixed runtime, and rotate everything it held. Do it in this order: preserve evidence, rebuild, then rotate. New secrets on an unpatched JVM would go to the same attacker. Rotating signing keys logs users out, so plan for that.

*Sources: Calif, Endor Labs, Prophet Security, GreyNoise, Semgrep (state on 18 November 2026, 08:00 UTC)*

---

#### DEFENSE-IN-DEPTH MEASURES

The fix is your vendor's fixed build and a restart. Until then, Red Hat calls -XX:-UseBASE64Intrinsics the preferred stopgap. Everything else in this section narrows the exposure or limits the damage, and none of it removes the bug. The first table shows what each control covers and what it leaves open.

| Control | What it covers | What it leaves open |
| --- | --- | --- |
| `-XX:-UseBASE64Intrinsics`, then a restart | The vulnerable path on that JVM. Red Hat: it "disables the hardware-accelerated Base64 implementation only. This is the preferred option, as it removes the vulnerable code path while leaving other AVX-512 optimizations in place." Calif recommends it too | OpenJDK 8 doesn't know the flag and won't start with it. No source says whether Oracle's Java 8 Performance Pack accepts it. It must reach the JVM (see where the flag goes). Base64-heavy work may slow down (our reading), and nobody has published numbers. A rebuild or a launcher change can drop it |
| `-XX:UseAVX=2`, then a restart | All AVX-512 code in the JVM, which includes the vulnerable path. The Canadian Centre and Google recommend it | x86-64 only: an ARM64 JVM won't start with it. It turns off the JVM's other AVX-512 code as well |
| Isolating internet-facing applications from public networks | The network route to the service. The Canadian Centre: "consider isolating internet-facing applications from public networks until a fix can be applied." | Services that have to stay reachable. The client-side case: a Java program that opens a TLS connection to a malicious server can be compromised even if it exposes no service |
| Validating Base64 input and limiting unauthenticated access | CISA: "restricting and validating Base64 input at the application boundary, enforcing input-size limits, and limiting unauthenticated access." | Size limits alone won't stop it, because the malformed input that triggers it is short (our reading of Endor Labs' description of the trigger). It only helps where you control the code that decodes the input |
| Request buffering (for example in nginx) | Calif says it frustrates some of its exploit chains | Calif: "Request buffering is not a general mitigation" |
| WAF or IPS signature | See the next table | Count-mode rules log and block nothing, and inspection limits apply. No claim is made that any of them blocks the bug |
| The fixed build, then a restart | The bug, once the build is installed and the JVM has restarted | Nothing for this CVE. It doesn't undo a memory read that already happened, so rotate secrets by the tiers under ADVANCED FORENSICS |

**WAF and IPS coverage on 18 November 2026**

| Product | State | Note |
| --- | --- | --- |
| AWS WAF managed rules | Known Bad Inputs version 1.28 adds the Java4Shell_BODY, Java4Shell_QUERYARGUMENTS and Java4Shell_HEADER rules. AWS: "The new rules in these versions use the Count action." | Count logs matches and blocks nothing until you change the action. AWS WAF inspects only the first 8 KB of headers, cookies and body (IONIX) |
| Snort community rules | Snort 2: 12 rules, SIDs 67502 to 67513 (8 commented out by default). Snort 3: 13 rules (SIDs 67502 to 67513 and 301754). Message: "SERVER-WEBAPP OpenJDK Base64 decoder remote code execution attempt" | They match specific carriers: a SAML artifact, a connector authorization header, a Jenkins header and MIME encoded words. A request that arrives another way isn't covered by them (our reading) |
| Fortinet FortiGuard | Threat Signal 6668: "FortiGuard IPS detection opportunities for crafted Base64 input through network inspection are under investigation", with endpoint vulnerability signatures for Oracle Java | The network IPS part is still under investigation, in Fortinet's words |
| Cloudflare WAF | No Java4Shell entry in the changelog (newest item 12 November) | Nothing to switch on. Cloudflare inspects only the first 128 KB of a body (IONIX) |
| Emerging Threats Open | Nothing yet (last build 17 November, 21:59 UTC) | |
| Sigma | Nothing yet | |
| Elastic | A community rule proposal only (issue 7199) | |
| VulnCheck | Snort, Suricata, Sigma and YARA rules, shipped with its exploit | For its Initial Access Intelligence customers only |
| Akamai | Property Manager rules don't cover the request body (IONIX) | Ask your vendor what it offers for this CVE |

Don't count on a WAF or IPS for this bug. This document makes no claim that any of them blocks it.

*Sources: AWS WAF managed rules changelog, Snort community rules, Fortinet Threat Signal 6668, Cloudflare WAF changelog, Emerging Threats Open, Elastic rules issue tracker, VulnCheck, IONIX, Calif, CISA alert, Canadian Centre for Cyber Security alert AL26-029, Qualys, Endor Labs, Red Hat bulletin RHSB-2026-018 (state on 18 November 2026, 08:00 UTC)*

**Scanner and feed coverage**

The entries below come from the vendors' own pages and feeds, so they say what a product lists, not what it finds on your hosts. A clean report still proves little. A version scanner can't see the CPU or the JVM flags, and a dependency scanner can't see the runtime. Here is what the data feeds held on 18 November 2026:

| Source | State on 18 November 2026 | What a clean result means |
| --- | --- | --- |
| NVD | Status "Received", with no CPE data and no NVD score. The page shows Oracle's 8.1 | A tool that reads NVD alone has no product data to match, so it will miss the CVE. A clean result there says nothing |
| Qualys | QID 389494, plus 389610 for Oracle Java SE and 389608 for Corretto | "Not flagged", not "not exposed". It can't see the CPU or the JVM flags, and CISA warns that Java runtimes may not appear as separate entries in an inventory |
| Tenable | Plugins 382091 ("Oracle Java SE Oracle CSPU Nov 2026 (Java4Shell)") and 382045 (Corretto 17) | The two plugins name Oracle Java SE and Corretto 17. Don't assume a clean report covers other vendors' builds or the flags |
| Rapid7 | An authenticated check, in its 17 November content release | It covers only the hosts the scan could log in to. "Not flagged" is not "not exposed" |
| Snyk | Lists RHEL 10 and CentOS 10 packages and the Conan openjdk package | A listing for the packages it tracks, not proof of exposure. A dependency scanner can't see the runtime |
| Distro feeds | Ubuntu, SUSE and Alpine have no entry. Debian lists openjdk-17, -21, -25 and -27 as unfixed. Red Hat has no errata, and its VEX file lists 138 products as known affected. Amazon Linux lists fixed packages | An empty feed says nothing. A tracker that lists a fixed package says it exists, not that your host runs it |
| Nuclei | A template for a version check was proposed at 07:00 UTC on 18 November. The pull request is open and not merged | No merged Nuclei template checks for this CVE today, so a clean Nuclei run says nothing about it |
| CISA KEV | Not listed (catalog 2026.11.17). CISA's SSVC entry says Exploitation none, Automatable no, Technical impact total | A queue that ranks by KEV won't raise it |
| EPSS | No score yet | A queue that ranks by EPSS has nothing to rank. Rank by exposure instead |

*Sources: NVD, Qualys, Tenable plugin pages, Rapid7, Snyk, distro trackers and VEX file, Nuclei templates pull requests, CISA KEV catalog and SSVC entry, FIRST EPSS API, CISA alert (state on 18 November 2026, 08:00 UTC)*

**The version number trap.** There are four traps here. The first is the October respins. Builds ending in .0.2 and .0.3 (17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 and 27.0.1.0.3) look newer than the October releases and are the last vulnerable builds. The fix is the .1 build. The second is vendor numbering. Corretto adds a fifth field (17.0.21.1.2), Azul Zulu has its own numbers (17.70.201), and some write-ups wrongly cite 17.0.11 and 21.0.3 as fixes (Upwind lists that as a wrong claim). Judge each build by its own vendor's list. The third is the copy of Java a product carries (Jira, Confluence, Elasticsearch and container images). It is separate from the server's system Java, and updating one doesn't update the other. The fourth is the running process. A JVM that was upgraded in place and not restarted still runs the old code, and a release file describes the runtime on disk. Where we inferred a status, check again when the vendor publishes a notice.

*Sources: Oracle Critical Security Patch Update, Amazon Corretto and Azul release data, Upwind, Atlassian and Elastic documentation, HotSpot source*

---

**What does NOT help:**

- Updating the system Java when the product carries its own runtime. Jira, Confluence, Elasticsearch and the Jenkins and Keycloak images need their own fix.
- Installing a fixed build without restarting. The running JVM keeps the old code.
- Judging by the version number alone: the .0.2 and .0.3 respins look newer, and vendors number builds differently.
- Trusting a tag name. Amazon rebuilt the Corretto images under their old tag names.
- Setting -XX:-UseBASE64Intrinsics where a Java 8 JVM reads it. OpenJDK 8 doesn't know the flag and won't start, and no source says whether Oracle's Java 8 Performance Pack accepts it.
- Setting the flag where it isn't read. JDK_JAVA_OPTIONS is read only by the java launcher, Elasticsearch strips both variables, and Keycloak's JAVA_OPTS replaces its defaults. Confirm with `jcmd <pid> VM.flags -all`.
- Relying on size limits alone. The malformed input that triggers the bug is short (our reading of Endor Labs' description of the trigger).
- Counting on request buffering. Calif: "Request buffering is not a general mitigation".
- Counting on a WAF rule. The AWS rules are in Count mode, Cloudflare and AWS WAF inspect only the first part of a request (IONIX), and Cloudflare has no entry. No claim is made that any of them blocks the bug.
- Reading a clean scanner report as "not exposed". A version scanner can't see the CPU or the flags, and NVD has no product data.
- Using `lscpu | grep avx512` as the CPU check. Skylake-SP and Cascade Lake print AVX-512 flags without VBMI.
- Assuming a service is safe because it sits on ARM64 or older Intel today. Workloads move between machine types.
- Waiting for KEV or an EPSS score. KEV doesn't list the CVE and EPSS has no score yet. Rank by exposure.
- Code from public repositories that call themselves checkers or mitigations. 25 repositories mention the CVE, and none is verified.

*Sources: Oracle Critical Security Patch Update, Calif, Qualys, Endor Labs, IONIX, AWS WAF managed rules changelog, Cloudflare WAF changelog, Red Hat bulletin RHSB-2026-018, Canadian Centre for Cyber Security alert AL26-029, NVD, CISA KEV catalog, FIRST EPSS API, GitHub repository search (state on 18 November 2026, 08:00 UTC)*

---

**Hardening that limits the damage**

None of this stops the bug. It limits what a successful attempt can do, and it is our advice, not a vendor's. What the JVM holds in memory and what its account can reach set the damage.

- Run each Java service as its own account with least privilege, and not as root. Give it read access only to the files it needs, and write access only to the few directories it must write to, such as logs, caches and temp files.
- Use short-lived tokens and credentials where you can, and load only the secrets each service needs. A heap read then gets less, and rotation after an incident is a small job. Give identity, single sign-on, CI and artifact servers signing keys and credentials that you can rotate without touching the rest of the estate.
- Restrict outbound traffic from Java services with an allow list at the host firewall, the security group or an egress proxy. It doesn't stop the bug, but it can break a reverse shell or a tool download after code execution. It also narrows the client-side case, where a Java program that opens a TLS connection to a malicious server can be compromised (our reading).
- Keep internet-facing Java services apart from hosts that hold other secrets, and from backends the service has no reason to reach.
- In a container, run the process as a non-root user, mount the filesystem read-only where the image allows it, and drop capabilities you don't need. Pin the base image by digest after you have checked it, and rebuild on a schedule so that new Java updates reach your images.
- Send `hs_err` crash logs, application logs and process-creation events to a place the host can't change (see Monitoring and alerting below).

*Sources: Calif. The rest is our own advice, not a vendor's.*

**Patch cadence and the silent window**

This bug gave little notice. The problem and the fix approach were public in an OpenJDK pull request from 9 September 2026 (09:12 UTC), about ten weeks before the release. The fix sat in the Java 27 update repository from 14 October (10:37 UTC) under the title "8393212: Base64 optimization improvements". Oracle reserved the CVE number on 22 October (04:13 UTC), and the October respins that shipped meanwhile (.0.2 and .0.3) don't have the fix. It reached the Java 17, 21 and 25 update repositories on 12 November (11:42 UTC). The coordinated release came on 17 November at 21:00 UTC.

- Set a written cadence that gets each Java update onto every runtime within days, with restart windows built in, and cover the runtimes inside products and images. A build that is installed and not restarted protects nothing.
- Don't rely on CVE alerts alone. A fix can sit in a public repository for weeks under a bland commit title, and the CVE record for this bug appeared on 17 November.
- Keep an emergency path outside the normal window for a runtime bug. Patch internet-facing JVMs on VBMI hardware first.
- Plan the next dates now. Google's masking on managed Java runtimes ends on 30 November 2026. Oracle's next Critical Security Patch Update is on 15 December 2026, and its next quarterly Critical Patch Update is on 19 January 2027. Oracle's 17.0.21.1 notes say it is not recommended to use that build after the January update.

*Sources: OpenJDK commit history and advisory, Oracle Critical Security Patch Update and 17.0.21.1 release notes, CVE record, Google Cloud support bulletins (state on 18 November 2026, 08:00 UTC)*

---

**Monitoring and alerting**

Turn the signals on before you alert on them. A rebuild wipes the host's own logs, so the copy that counts is the one that left the host. Write the queries in your own SIEM's syntax from the patterns in the table. Baseline first: your normal crash rate, your scripts and your usual destinations decide the thresholds.

| What to watch | Where it comes from | Alert when |
| --- | --- | --- |
| Build, flag and restart state | The Phase 1 and Verification commands, run on a schedule | An internet-facing JVM on VBMI hardware runs an affected build without the stopgap, or started before the upgrade |
| Flag drift | `jcmd <pid> VM.flags -all`, run on a schedule | UseBASE64Intrinsics is true again after the stopgap, or a managed platform that relied on C1 only starts to run C2 (Azure Functions) |
| JVM crash logs | `hs_err` crash logs, read from a copy held off the host | Any, until you know your baseline. Repeated crashes with a Base64 decoder frame, clustered by source, at once |
| Swallowed exceptions | Application logs: `IllegalArgumentException` from the Base64 decoder | A burst on an endpoint that needs no login |
| Process creation | EDR or audit events for processes whose parent is a Java process | A shell or download tool that isn't in your baseline |
| Outbound connections | Firewall or flow logs for Java services | A destination the service doesn't normally use |
| WAF matches | AWS WAF logs for the Java4Shell rules (Count mode) | Any match |
| Restarts | Orchestrator restart counts and service manager events | A restart that no deploy explains |

Watch for outside signs that the picture has changed. In our reading, crashes are the most likely harm this week, the memory read can be quiet, and code execution needs work tailored to each product. The signs that this has changed would be Calif's release of its product chains, a merged Nuclei template, a Metasploit module or a KEV listing.

---

#### ADVANCED FORENSICS

A restart destroys the memory of the JVM, and a rebuild wipes the host. A memory read can leave no crash (our reading), and we have no source that says what an attempt leaves behind, so volatile state may be the only evidence. On any JVM that showed one of the signals above, capture first and patch second. Work in order of how fast things disappear: processes and connections first, then memory, then logs, then config and launch scripts, then the disk.

**Capture volatile state before any restart:**

Bring trusted tools to the host, and send each output to a file on an evidence volume or a remote destination, not to the application disk.

```bash
# Every process with its parent, owner and start time
ps -eo user,pid,ppid,lstart,args
# The same as a tree, to see what each process started (Linux)
ps -eo user,pid,ppid,lstart,args --forest
# Running JVMs, then the version and flags of each one (run as the JVM's user or root)
jcmd -l
jcmd <pid> VM.version
jcmd <pid> VM.flags -all
# Service log lines kept by the journal (run as root). Replace <service> with the unit name
journalctl -u <service> --no-pager
```

- Connections: for established connections, use your EDR or flow logs.
- Memory: see "Preserving evidence before a restart" under DETECTION & FORENSICS for the heap dump and `gcore` warnings. A dump or a core file holds every secret the JVM had, so encrypt it, hash it and limit who can read it. Reading one takes specialist tools, so capture it and hand the analysis to someone who does this for a living. A hypervisor snapshot that includes memory works too. Keep the version output with it.
- Logs: the `hs_err` crash logs (the `find` commands above), the application logs (rotated ones too), the proxy and WAF logs, the AWS WAF Count-mode matches, the container logs and the journal.
- Config: the product's own settings, the launcher scripts that set the JVM options, and the environment the service starts with. They show which flags the JVM ran with.
- Disk: an image or a snapshot.

Then isolate the host: cut its network at the switch, the security group or the hypervisor, and don't shut it down. For a container, don't remove it. Export or snapshot its filesystem with your runtime's tools before you replace it.

A shell, a download tool or an unknown binary started by a Java process, and not in your baseline, is an incident. If its start time lines up with crashes in the crash logs, that is the sequence to chase. A clean result doesn't clear the JVM: the process commands list live processes only, and anything that has already exited leaves nothing.

**When to rebuild instead of patching in place:**

Once an attacker has run code inside the JVM, everything the service account can write may have changed. The process list, the file listing and the logs come from a system the attacker has touched, so a scan that finds nothing proves nothing. A fixed build stops new attempts and removes nothing that is already installed. This is our reasoning, not a vendor statement, and it is standard practice after a code-execution compromise.

If a host shows a shell, a new file or an unexplained outbound connection, or you can't rule one out, rebuild it:

- Preserve first: process and connection state, logs, memory if you can, and a disk image or snapshot.
- Rebuild from a known-good image that carries a fixed runtime, not from a copy of the old system disk.
- Restore content and data only after you have checked them. Don't restore scripts, cron entries, unit files or configuration from the old host without reading them.
- Rotate everything the host could read or reach, by the tiers below. Rotate after the rebuild, not before.
- Treat every container that ran from a compromised image or on a compromised host as exposed, with the secrets mounted into it.
- Check the neighbours: every system that the host could reach with the credentials it held.

Patching in place is acceptable for a JVM with no indicator and no link to an attempt.

**Evidence handling:**

- Record who collected what, when, from which host, and with which tool and version. Record the host's clock offset from UTC, and keep every timestamp in UTC.
- Hash each item with SHA-256 right after you collect it, write the hashes to a separate file, and keep a read-only copy off the host.
- Work on copies. Keep the originals untouched.
- Encrypt memory dumps, logs and exports, at rest and in transit, and limit who can read them.
- Log every command you run on the suspect host, and note whether it only read or changed something.
- If you expect legal action or an insurance claim, image the disk (a volume snapshot on a cloud server) before you rebuild.

**Building the timeline:**

Put every source on a single UTC timeline and mark each entry: exposure (an exposed build was running), attempt (crashes or odd requests), or possible success (a process, a response or a connection that isn't in your baseline).

| Source | What it gives you |
| --- | --- |
| Package and restart history | When each JVM last ran an exposed build, and when it installed and restarted into the fix or took the flag |
| JVM crash logs | The `hs_err` files, with their times and the Base64 decoder frame if there is one |
| Application, proxy and WAF logs | Malformed Base64 and exception bursts, the client addresses around each crash, AWS WAF Count-mode matches |
| Process start times | The `lstart` column for every hit in the process hunt |
| Firewall, flow and proxy logs | Outbound connections, and what the proxy saw of the client |
| Platform logs | Cloud audit logs and instance events, and for containers the orchestrator events |
| Credential use | Where the secrets from the JVM were used afterwards, and from which addresses |

No published attack pattern exists for this CVE, so we can't tell you which request sequence to look for. The sequence to chase is a run of crashes or exceptions followed by a process, a response or a connection that isn't in your baseline.

**The window to review:**

No exploitation is confirmed at the cut-off. CISA's SSVC entry says Exploitation none, and KEV doesn't list the CVE. The Canadian Centre says it "is not aware of active exploitation at this time, but that can change quickly", and VulnCheck says the CVE is "not known to be exploited in the wild at time of writing". Tenable, Qualys and Horizon3 report none, and no source names a threat actor, campaign or malware. VulnCheck has a full exploit that it makes available to its paying customers, and Calif says it will publish its product chains later. Scanner traffic exists: at 07:18 UTC GreyNoise counted 3 IPs, 53 requests and 0 successful intrusions.

| Window | Starts | Use it when |
| --- | --- | --- |
| Full window | 9 September 2026 | An internet-facing JVM on an affected build and VBMI hardware holds sensitive data, and you keep logs that long. A public OpenJDK pull request described the problem and the fix approach that day, about ten weeks before the release. It is the earliest date anyone could have worked from public information. No source says anyone did, so treat it as a margin and not as a known exposure date |
| Disclosure | 17 November 2026, 21:00 UTC | Always, for every affected JVM. The OpenJDK advisory and Oracle's Critical Security Patch Update were released together. The CVE record followed at 21:32 UTC, and VulnCheck made a full exploit available to its customers at 23:00 UTC |

The shortest window you should use starts at the disclosure. Weigh the hours around it more heavily, and start a few hours earlier if your logs allow: Calif said at about 16:11 UTC on 17 November that details had leaked. The window ends when each JVM runs a fixed build or has the flag, not on the day you installed the package.

*Sources: OpenJDK pull request and advisory, Oracle Critical Security Patch Update, CVE record, CISA SSVC entry and KEV catalog, Canadian Centre for Cyber Security alert AL26-029, VulnCheck, Calif, Tenable, Qualys, Horizon3, GreyNoise (state on 18 November 2026, 08:00 UTC)*

**Secret rotation tiers (our reading):**

Patching closes the hole, and it doesn't undo a memory read. A memory read can leave no crash, so a clean log can't tell you which tier a service is in. These tiers are our reading, not a vendor's advice.

- **Tier 1:** an internet-facing identity, single sign-on, CI or artifact server that ran an affected build on VBMI hardware with the intrinsic on, and was neither patched nor flagged after 21:00 UTC on 17 November 2026 (the coordinated release, by Calif's account; a commercial exploit followed two hours later). After patching, rotate its signing keys and stored credentials, and invalidate the sessions and tokens it issued.
- **Tier 2:** any other affected service. Rotate the secrets it held if your logs show the warning signs from DETECTION & FORENSICS at any point since 9 September 2026.
- **The list:** database passwords, API keys, cloud credentials, OAuth and OIDC client secrets, JWT and SAML signing keys, TLS private keys in Java keystores, and secrets in configuration or the environment.

Do it in this order: preserve evidence, patch or rebuild, then rotate. New secrets on an unpatched JVM would go to the same attacker. Rotating signing keys logs users out, so plan for that.

*Sources: our reading, built on the OpenJDK advisory, Oracle's Critical Security Patch Update and VulnCheck (state on 18 November 2026, 08:00 UTC)*

**Public repositories named after the CVE:** at 07:46 UTC on 18 November, 25 GitHub repositories mentioned the CVE. By their descriptions, 12 are tools, scanners, detection or mitigation projects, 5 are labs or local reproductions, 2 claim exploits, 2 are write-ups and 4 are empty. None is verified. Running unknown proof-of-concept code is a common way to get compromised, so don't test your hosts with it, and that includes the defensive tools. Pentestit's advice: "Read any script before you run it." If anyone on your team ran one against a real host or a laptop, treat that machine as suspect. We have no hashes, addresses or request signatures for this CVE, and GreyNoise's tracker shows "Block candidates (0)", so there is nothing to put on a blocklist.

*Sources: GitHub repository search, GreyNoise, Pentestit (state on 18 November 2026, 08:00 UTC)*

**When to bring in outside help:**

- A shell or download tool started by a Java process, and you can't explain it from your baseline
- Repeated crash logs with a Base64 decoder frame, followed by a new file or an outbound connection from a Java process, on a JVM that wasn't patched or flagged at the time
- Secrets from a suspect service were used from addresses you don't recognise
- You hold a heap dump or a core file and nobody on the team can read it
- An internet-facing identity, single sign-on, CI or artifact server was exposed after the disclosure, and the list of keys, credentials and tokens to rotate is long or unclear
- A JVM was already restarted or rebuilt and its logs rotated, and it handled customer or regulated data. The question then changes from "was it exploited" to "what could the JVM read", and the notification duties in COMPLIANCE & LEGAL REQUIREMENTS apply

Do not wipe or rebuild a suspect host before you have preserved it.

---

## BUSINESS IMPACT ANALYSIS

### Financial impact scenarios

The scenarios stay qualitative. No source for this bug gives cost figures, so none are given here.

#### Scenario 1: Prevention (patch and flag this week)

**Costs:**

- Staff time: finding every Java runtime (the system Java, the copies bundled inside products, container images, golden images and VM templates), checking which ones run on x86-64 hosts with AVX-512 VBMI, then a fixed build or a flag, and a restart, for each
- Testing: a regression pass per critical service after the restart, covering logins, tokens, SAML flows and monitoring. The flag may slow Base64-heavy work, and nobody has published numbers (our reading: test one node first)
- Restarts: a fixed runtime on disk doesn't fix a JVM that is still running, so every JVM that used the old runtime needs a restart, and container images need a rebuild and a redeploy
- Version traps: the .0.3 respins look newer than the October releases but are the last vulnerable builds, vendors number their builds differently (Corretto adds a fifth field, Azul Zulu has its own numbers), and the copy of Java inside a product is separate from the server's system Java
- Vendors with no fix yet: at the cut-off Eclipse Temurin, Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux had not shipped one, so those hosts need the flag first and an update when the advisory lands
- Downtime: none if you restart one node at a time behind a load balancer, a short maintenance window for a single server

**Benefits:**

- No breach costs, no notifications, no letters from regulators
- An accurate Java inventory that includes the copies nobody listed. CISA: "JDKs and Java runtimes may not appear as separate entries in software inventories". You will want it for the next advisory
- The same release carries other fixes: Oracle's November update has 11 Java SE fixes, and CVE-2026-114941, CVE-2026-114943 and CVE-2026-114946 are separate flaws. CVE-2026-114946 (4.8, Compiler) reaches every line including 8 and 11

*Sources: Oracle Critical Security Patch Update, OpenJDK advisory, Red Hat bulletin RHSB-2026-018, Amazon Linux, Azul, SAP and Arch Linux package notices, Adoptium release status, CISA alert*

---

#### Scenario 2: An identity or single sign-on server taken over

**How it plays out:** Calif says it achieved code execution before login in Keycloak and PingFederate, among other products, in their default configurations. Its product chains are private, and independent labs have so far reproduced crashes and a memory leak but not code execution (The Hacker News). So this is a plausible chain, not an observed one: no exploitation in the wild was confirmed at the cut-off. Our reading is that a server which signs logins holds the keys other systems trust, so a takeover would not stay on that one server. Keycloak's official image uses the Red Hat java-21-openjdk-headless package, so its fix follows Red Hat's errata, and Red Hat had none at the cut-off. PingFederate's zip install uses a Java you install yourself.

**Costs:**

- Forensics and incident response, legal counsel, breach notification
- Rotating signing keys and stored credentials (JWT and SAML signing keys, OAuth and OIDC client secrets), and invalidating the sessions and tokens the server issued. Every system that trusted those tokens is in scope
- Downtime while you rebuild the server from a clean image
- Regulatory exposure if personal data was involved
- Reputational damage, and higher cyber insurance premiums at renewal

*Sources: Calif write-up, The Hacker News, Red Hat bulletin RHSB-2026-018, Keycloak container build files, Ping Identity documentation*

---

#### Scenario 3: A CI or artifact server taken over

**How it plays out:** Calif says it achieved code execution before login in Jenkins and JFrog Artifactory, and after login in Gerrit and Spinnaker. Our reading is that a build or artifact server holds credentials for source repositories, cloud accounts and deployment, and what it builds runs somewhere else, so a takeover reaches well past the server itself. Independent labs have not reproduced code execution, and VulnCheck says its full exploit is available to its Initial Access Intelligence customers. The official Jenkins image carries a Temurin runtime that gets the fix only after Adoptium publishes it and Jenkins rebuilds the image, and Temurin had not shipped the fix at the cut-off. We could not verify which Java Artifactory carries, because its documentation was unreachable.

**Costs:**

- Forensics and incident response, legal counsel
- Rotating every credential the server held (repository tokens, cloud credentials, signing keys) and invalidating the sessions it issued
- Working out which builds, packages and images came from a suspect server, and whether to trust them
- Notifying customers or partners if what you shipped may be affected (our reading)
- Downtime while you rebuild the server from a clean image. Build servers start shells legitimately, so "a Java process started a shell" is a weak signal here

*Sources: Calif write-up, Adoptium release status, Jenkins container build files, JFrog documentation (unreachable)*

---

#### Scenario 4: A quiet memory read that leaks secrets

**What's different:** Calif calls this JavaBleed, "the ability to leak contents from the Java heap, which may hold PII, private keys, other secret keys, and tokens". It is not a separate CVE. Blackpoint, per The Hacker News, ran a memory-read test that "worked in all 30 runs". Prophet Security warns that "Many frameworks catch the exception and reject the request without logging it, so a quiet application log does not rule out an attempt." Our reading is that a read can leave no crash and no log entry you would recognise, and that patching closes the hole without undoing what was already read.

**Costs:**

- Rotating the secrets a suspect service held: database passwords, API keys, cloud credentials, OAuth and OIDC client secrets, JWT and SAML signing keys, TLS private keys in Java keystores, and secrets in configuration or the environment
- Investigating every system those secrets open (databases, payment APIs, cloud accounts, email)
- Notification if personal data was in the heap at the time
- Evidence against speed: a heap dump forces a full garbage collection unless -all is given and writes a heap-sized file full of secrets, and gcore needs ptrace rights. Treat dumps and crash logs as sensitive
- No network control recovers data already read from memory

*Sources: Calif write-up, The Hacker News, Prophet Security, OpenJDK diagnostic command source, Linux kernel Yama documentation*

---

#### Scenario 5: Denial of service from crashes

**What's different:** this is the outcome the independent labs have reproduced. VulnCheck: "triggering the memory corruption to crash an affected JVM (a DoS) is trivial - if you can find and reach a sink that uses the vulnerable Base64 decode logic", and "A single request usually will not crash a default-configured server... but a simple burst of requests reliably brought the service down in our testing." Upwind reproduced the overflow on an AWS c6i instance (Intel Ice Lake). Upwind says that with an exact-size output buffer the overflow corrupted the next object in 97% of rounds and eventually crashed the JVM. Blackpoint, per The Hacker News, crashed a test Spring Boot application with about 28,300 malformed login requests over roughly 20 seconds. Equixly: "Denial of service is the realistic impact." Calif says a badly placed write "could cause the JVM to crash, but in many instances, we can simply try again", so even a failed code-execution attempt costs you availability.

**Costs:**

- Lost availability for the service, restart loops, and the support load that comes with them
- On-call time spent on crashes that look like application or platform faults
- Investigation effort to tell crash noise from an attack. Endor Labs' signature is repeated hs_err crashes with a compiled Base64$Decoder.decode0 frame, clustered by source, and no JDK vendor has confirmed it. A crash on an exposed server needs an explanation (see the EMERGENCY row in the DECISION MATRIX)

*Sources: VulnCheck, Upwind, The Hacker News, Equixly, Calif write-up, Endor Labs*

---

#### Scenario 6: Products that bundle Java with no vendor fix yet

**What's different:** a normal runtime update can't fix these today, because the Java inside the product is separate from the system Java. Jira and Confluence installers bundle Eclipse Temurin, and Temurin had not shipped the fix at the cut-off. Elasticsearch runs its bundled JDK by default, and its development branch pins 27.0.1.0.3, an affected build. The official Tomcat and Kafka container images are built on eclipse-temurin. We found no statement from Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache (Tomcat, Kafka, Solr), Cisco, IBM or SAP, and could not check Ping Identity or Broadcom. This analysis can't tell you when any of them will ship, so the wait has no known end date.

**Costs:**

- Exposure for as long as the vendor takes, with the fix out of your hands
- A compensating control in the meantime: the flag set through the product's own settings (the FAQ below shows where it goes for each product), plus the Canadian Centre's advice to "consider isolating internet-facing applications from public networks until a fix can be applied"
- Chasing the vendor for a written answer on whether the product is affected and when a fix ships
- Removing the flag once the fixed runtime is confirmed, and a supported swap of the runtime or a migration where a vendor won't ship a fix

*Sources: Atlassian, Elastic, Jenkins, Keycloak, Apache and Docker official image build files, Adoptium release status, Canadian Centre for Cyber Security alert AL26-029, vendor pages (no statement found)*

---

### Operational impact timeline

**Hour 0-24: Inventory, flag and patch**

- Platform and ops teams pulled off roadmap work
- A list of every Java runtime you run: host, container image or bundled copy, the live version (from jcmd, not from a file on disk), whether the CPU has AVX-512 VBMI, whether the service is internet facing, and which JVM flags are set
- Fixed builds installed where your vendor ships one, JVMs restarted and images rebuilt: internet-facing services on VBMI hardware first, starting with identity and single sign-on servers, CI and artifact servers, and Jira and Confluence
- The flag -XX:-UseBASE64Intrinsics on every JVM that must wait for a restart window or a vendor fix
- Decisions on products that bundle Java

**Day 2-7: Verification**

- Confirm on every host that each live JVM runs the fixed build or shows the flag, not only that the package is updated
- Log review for JVM crash logs, restart counts, bursts of IllegalArgumentException from java.util.Base64$Decoder, Java processes starting shells, and new outbound connections, from 9 September 2026 where your retention allows
- Rotating the signing keys and stored credentials of any first-tier server (an internet-facing identity, single sign-on, CI or artifact server on an affected build and VBMI hardware that was neither patched nor flagged after 21:00 UTC on 17 November 2026), after patching it, and invalidating the sessions and tokens it issued
- Chasing vendors for written answers: Temurin (Adoptium release-status issue 326), Microsoft, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux and AlmaLinux, and the product vendors with no statement
- Taking the flag off where the fixed runtime is confirmed

**Week 2-4: Hardening**

- Move retired Java lines (18 to 20, 22 to 24 and 26) to 21.0.13.1, 25.0.5.1 or 27.0.1.1, because they get no fix
- Retire golden images, VM templates and autoscaling launch configurations that still carry an affected runtime
- Take the November updates on Java 8 and 11 hosts too, because they fix other flaws (Oracle's baselines are 1.8.0_513-b04 and 11.0.33.1+4)
- New detection (crash-log alerts, restart counts, Java processes starting shells) and longer log retention
- Plan for the dates ahead: 30 November 2026 (Google's CPU-feature masking on managed Java runtimes ends), 15 December 2026 (Oracle's next Critical Security Patch Update) and 19 January 2027 (Oracle's next quarterly Critical Patch Update, after which Oracle's 17.0.21.1 notes say it is not recommended to use that build)

**Month 2-6: Only if you found a compromise**

- Regulator questions, customer communications, possible claims
- Audit follow-ups and insurer reviews

*Sources: Oracle Critical Security Patch Update, OpenJDK advisory, Adoptium release status, Google Cloud bulletin GCP-2026-082, vendor and distro advisories, Oracle 17.0.21.1 release notes*

---

### Cost-benefit analysis

| Option | Effort | What's left exposed | Verdict |
| --- | --- | --- | --- |
| Fixed build and restart now | A runtime update and a restart per JVM (one node at a time behind a load balancer), plus rebuilt container images | Nothing known for this CVE once the live JVM runs the fixed build | Do this |
| -XX:-UseBASE64Intrinsics until you can patch | Add the flag where it works (see the FAQ on where it goes), restart, test one node first | Nothing for this bug while the flag is on: Red Hat says it "disables the hardware-accelerated Base64 implementation only". Base64-heavy work may slow down, and the other November fixes stay open | A bridge for days, not weeks |
| -XX:UseAVX=2 until you can patch | The same, on x86-64 only (an ARM64 JVM won't start with it) | The vulnerable path is off, at the price of turning off all AVX-512 code in the JVM | Second choice |
| Network and WAF controls | Isolate internet-facing applications, restrict and validate Base64 input, AWS WAF Known Bad Inputs 1.28 (Count mode only until you change the action) | Whatever gets through. Size limits alone won't stop it, because the malformed input is short (our reading), and WAF inspection limits apply (Cloudflare inspects the first 128 KB of a body, AWS WAF the first 8 KB). Nothing recovers data already read | A layer, not a fix |
| Move retired Java lines | A migration project per application | Nothing once moved. Until then everything, because no fix will come | Required. Internet-facing first |
| Product with bundled Java waiting on its vendor | A written query to the vendor, plus the flag through the product's settings | Everything the flag doesn't cover, until the vendor ships | The flag now, the vendor's fix when it ships |
| Wait | None today | Everything | Not acceptable for an internet-facing service on VBMI hardware with an affected build. The problem and the fix approach were public from 9 September 2026, the coordinated release came at 21:00 UTC on 17 November (Calif's stated time), and VulnCheck made a full exploit available to its paying customers two hours later |

*Sources: Oracle Critical Security Patch Update, Red Hat bulletin RHSB-2026-018, Canadian Centre for Cyber Security and CISA alerts, AWS WAF managed rules changelog, IONIX, Endor Labs, VulnCheck*

---

## COMPLIANCE & LEGAL REQUIREMENTS

### Regulatory notification obligations

If you find signs of compromise, these timelines may start running. A clean update triggers none of them, and a JVM crash on its own is not a personal data breach. Whether personal data was reached is a legal judgment that depends on what the JVM held in memory and could read. Calif says the memory read can expose "PII, private keys, other secret keys, and tokens" from the Java heap, and an attacker who runs code in the JVM can read whatever the application can. This is a summary, not legal advice.

#### GDPR (EU) and UK GDPR

- **Timeline:** 72 hours to notify the supervisory authority after becoming aware of a personal data breach, unless it's unlikely to put people at risk
- **Individuals:** without undue delay if the risk to them is high
- **Fines:** up to EUR 20 million or 4% of worldwide annual turnover (UK: GBP 17.5 million or 4%)
- *Source: GDPR Articles 33, 34 and 83*

#### NIS2 (EU essential and important entities)

- **Early warning:** within 24 hours of becoming aware of a significant incident
- **Incident notification:** within 72 hours
- **Final report:** within one month
- *Source: Directive (EU) 2022/2555, Article 23*

#### India: CERT-In and DPDP

- **CERT-In:** report covered cyber incidents, including unauthorised access and compromise of systems, within 6 hours of noticing them
- **DPDP Act 2023:** breach-reporting duties phase in under the DPDP Rules 2025, so check whether they apply to you yet
- *Source: CERT-In Directions under Section 70B(6) of the IT Act, 28 April 2022*

#### SEC (US-listed companies)

- **Timeline:** Form 8-K Item 1.05 within four business days of determining that a cybersecurity incident is material
- *Source: SEC cybersecurity disclosure rules (2023)*

#### HIPAA (US healthcare data)

- **Timeline:** notify affected individuals without unreasonable delay, and no later than 60 days after discovery. HHS too, and the media if more than 500 residents of a state or jurisdiction are affected
- *Source: 45 CFR 164.400-414*

#### US state breach laws

- All 50 states have breach notification laws. Timelines and triggers vary by state

#### US federal agencies: CISA BOD 26-04

- **Directive:** BOD 26-04 (10 June 2026) revoked BOD 22-01. Its clock starts when CISA adds the CVE to the KEV catalog, or when the agency identifies the CVE on an asset, whichever comes first. Days are calendar days
- **Timelines for this CVE:** CISA's own SSVC entry gives Automatable no and Technical impact total. With those values, a publicly exposed asset gets 14 days while the CVE is not in KEV, and 3 days plus forensic triage once it is. A non-exposed asset gets "fix on system upgrade" before a KEV listing and 14 days after
- **Status:** the CVE was not in KEV at the cut-off (catalog 2026.11.17). The directive's Phase III (within 180 days of issuance, about 7 December 2026 by our count) brings the full table into force, and the KEV timelines apply now
- *Source: CISA BOD 26-04 and its remediation timelines table, BOD 22-01, CISA SSVC entry in the CVE record*

#### PCI DSS v4.0.1 (payment card environments)

- **Requirement 6.3.3:** patches for critical vulnerabilities, as ranked by your own process, "are installed within one month of release". The standard itself was unreachable at the cut-off, so this comes from secondary summaries, and they disagree on whether v4.0.1 still covers high-severity patches
- **Our reading:** about 17 December 2026 for the builds released on 17 November, and the day each product vendor ships for products that bundle Java
- *Source: secondary summaries of PCI DSS v4.0.1 requirement 6.3.3 (the PCI SSC standard itself was unreachable)*

---

### Documentation requirements checklist

**Create and maintain:**

- [ ] **Incident timeline** with precise timestamps
    - When the issue became public (the fix approach in an OpenJDK pull request from 9 September 2026, the fix in the Java 27 update repository from 14 October, in the Java 17, 21 and 25 update repositories from 12 November, and the coordinated release with Oracle's patch at 21:00 UTC on 17 November 2026 (Calif's stated time), with a commercial exploit two hours later)
    - When your organization learned about it
    - When inventory, patching, flags, restarts and verification finished
- [ ] **Technical details:**
    - Inventory of Java runtimes (system, bundled and in container images), with the vendor, the full version string, whether the host CPU has AVX-512 VBMI and whether the service is internet facing
    - Versions before and after patching, and the JVM flags in force, with restart times
    - Any evidence of compromise (crash logs, restarts, odd processes)
    - Stopgaps applied and removed (-XX:-UseBASE64Intrinsics, -XX:UseAVX=2, WAF rule actions)
- [ ] **Business impact assessment:**
    - Systems and data at risk
    - Customer impact
- [ ] **Decision log:**
    - Who authorized what, and why
    - Risk decisions on products that waited for a vendor, on retired Java lines, and on nodes where you could not tell whether VBMI was visible to the JVM
    - The reasoning behind any "no compromise" conclusion. No indicators of compromise have been published beyond scanner traffic, so "we found nothing" is weaker evidence here than it would be for a bug with a known fingerprint. Semgrep: "A WAF rule, a lack of alerts or a lack of crashes does not prove that a runtime is patched or that no attempt occurred."
- [ ] **Communications log:**
    - Who was told what, and when

**Retention:** follow your industry's record-keeping rules. Seven years is a common default.

---

### Insurance considerations

- [ ] Check that your cyber policy is active and what it covers (investigation, business interruption, liability, notification costs)
- [ ] Check the notification deadline in the policy. Many require notice within 24 to 72 hours of a suspected incident
- [ ] Check whether you must use the insurer's panel of response firms
- [ ] Keep evidence of your patching speed: dates, versions and restart times. Insurers look hard at known, unpatched vulnerabilities

**Call your broker straight away if:**

- You find indicators of compromise
- You're taking systems offline or running on stopgaps for more than a few days
- You're unsure what your policy covers

---

## DECISION MATRIX

### What should we do right now?

| Your situation | Immediate action | Priority | Timeline |
| --- | --- | --- | --- |
| The live JVM runs a fixed build (17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 or your vendor's equivalent, checked against that vendor's own list) | Document it, keep monitoring | LOW | This week |
| Fixed runtime installed, JVM not restarted, or container image not rebuilt | Restart now (one node at a time), rebuild and redeploy images | HIGH | Today |
| Internet-facing Java service on an affected build, on an x86-64 host with AVX-512 VBMI, JVM defaults left on | Install the fixed build and restart. If your vendor has none yet, or the restart has to wait, add -XX:-UseBASE64Intrinsics and restart | CRITICAL | Today |
| Identity and single sign-on servers (Keycloak, PingFederate), CI and artifact servers (Jenkins, Artifactory), and Jira and Confluence, internet facing | First in line. Fixed build or flag today. If the server stayed unpatched and unflagged after 21:00 UTC on 17 November 2026, rotate its signing keys and stored credentials after patching and invalidate the sessions and tokens it issued | CRITICAL | Today, before everything else |
| Internal services on VBMI hardware, reachable only from trusted networks | Fixed build, or the flag, then restart | HIGH | 48 hours |
| Java programs on VBMI hardware that open TLS connections to servers you don't control, even if they expose no service | Fixed build or the flag. Calif's client-side claim: "A Java program that opens a TLS connection to a malicious server can be compromised, even if it exposes no service of its own." How that path works is not public | HIGH | 48 hours |
| Product that bundles its own Java and waits on its vendor (Jira, Confluence, Elasticsearch, Jenkins and Keycloak images, PingFederate, Tomcat, Kafka) | Apply the flag through the product's own settings today (the FAQ below shows where it goes), restart, ask the vendor in writing, update the day the fix ships | CRITICAL if internet facing on VBMI hardware, otherwise HIGH | Today, or 48 hours |
| Oracle Java 8 Performance Pack (8u511b33-perf and earlier) | Affected. Install 8u513-perf (1.8.0_513-perf-b4). Standard Java 8 does not know -XX:-UseBASE64Intrinsics, and no source says whether the Performance Pack does, so don't count on the flag there. If you try it, test one JVM first | CRITICAL if internet facing on VBMI hardware, otherwise HIGH | Today, or 48 hours |
| Retired Java lines (18 to 20, 22 to 24 and 26) | No fix will come (Amazon marks its 22, 23, 24 and 26 packages "No Fix Planned"). Move to 21.0.13.1, 25.0.5.1 or 27.0.1.1, and use the flag until you have | CRITICAL if internet facing on VBMI hardware, otherwise HIGH | Today, or 48 hours |
| ARM64 (AWS Graviton, Ampere) or x86-64 without VBMI | Not exposed on the hardware side. Take the fixed build in the normal window, because workloads move between machine types. In VMs, run the CPU check inside each guest | LOW | Normal window |
| Java 8 (standard), Java 11, or Java 17.0.0 to 17.0.5 | Not affected by this CVE: no AVX-512 decode intrinsic in those. Take the November updates anyway, because they fix other flaws | LOW | Normal window |
| Google managed Java 17, 21 and 25 runtimes on App Engine standard and Cloud Run second generation (including 2nd gen Cloud Run functions) | Google masked AVX-512 VBMI as an interim platform safeguard through 30 November 2026. Plan the update or the flag before then | MEDIUM | Before 30 November 2026 |
| Google platforms outside that safeguard (Cloud Run first generation, Cloud Functions 1st gen, App Engine flexible, Cloud Run jobs and worker pools, custom containers, deployments without automatic base image updates) | No masking. Treat them as any other affected runtime, using the rows above | CRITICAL if internet facing on VBMI hardware, otherwise HIGH | Today, or 48 hours |
| Azure Functions (Java) on the default flags | The worker starts the JVM with -XX:+TieredCompilation -XX:TieredStopAtLevel=1, so only C1 runs and the default doesn't reach the stub. Check that nobody re-enabled C2 (for example -XX:TieredStopAtLevel=4 or -XX:-TieredCompilation in JAVA_OPTS, languageWorkers__java__arguments or _JAVA_OPTIONS). The worker issue checked whether the intrinsic is used, not memory corruption | LOW, HIGH if C2 is back on VBMI hardware | Normal window, or 48 hours |
| Don't know which hosts run Java, or which have VBMI | Run the inventory commands | CRITICAL | 2 hours |
| On an exposed service: crashes you can't explain (hs_err crash logs, repeated restarts), a Java process starting shells or download tools, or new outbound connections from a Java process | Start incident response. Capture the process list, network connections and logs before any restart. Treat heap dumps and crash logs as sensitive | EMERGENCY | Immediately |

*Sources: Oracle Critical Security Patch Update, OpenJDK advisory, Red Hat bulletin RHSB-2026-018, Calif write-up, Amazon Linux advisory, Google Cloud bulletin GCP-2026-082, Azure Functions Java worker issue 909 and Azure Functions Java reference*

---

### Risk decision framework

**For each Java runtime, container image and bundled copy:**

```
Step 1: Hardware and build (take the first line that matches)
- Java 8 (standard), Java 11, Java 17.0.0 to 17.0.5: not
  affected by this CVE                                       LOWER
- ARM64, or x86-64 without AVX-512 VBMI                      LOWER
- x86-64 with AVX-512 VBMI (Intel Xeon Ice Lake, Sapphire
  Rapids, Emerald Rapids or Granite Rapids, AMD Zen 4 and
  later, Intel client Ice Lake, Tiger Lake and Rocket
  Lake), affected build, JVM defaults on                     HIGH
- Cloud node pool where any node has VBMI (the same image
  can be exposed on one node and safe on the next; our
  reading)                                                   HIGH

Step 2: Is the vulnerable path on in this JVM?
- UseAVX is 3, UseBASE64Intrinsics is true, C2 is running    HIGH
- UseBASE64Intrinsics false, or UseAVX 2 or lower, or
  TieredStopAtLevel 1 (C1 only)                              LOWER

Step 3: Exposure path
- Internet-facing service that decodes Base64 from requests
  (HTTP Basic credentials, SAML artifacts, CSRF tokens,
  MIME encoded words)                                        HIGH
- Same, reachable only from trusted internal networks        MEDIUM
- Program that opens TLS connections to servers you don't
  control (the client-side variant)                          MEDIUM

Step 4: Role and what it holds
- Identity, single sign-on, CI and artifact servers, Jira
  and Confluence                                             HIGH
- Signing keys, credentials, personal, payment or health
  data in memory                                             HIGH
- Public content only, no secrets                            LOWER

Step 5: Action
Internet facing + any other HIGH   Fixed build or flag today
Internal + any other HIGH          Within 48 hours
Everything else                    Normal window
```

Two situations are easy to miss. A scanner or a package list can't see the CPU or the JVM flags, so a host that looks affected on paper may be clear, and a host that looks clear on paper may carry a bundled runtime that nobody listed. And a Java 8 or 11 host is not affected by this CVE but still needs the November updates, which fix other flaws.

*Sources: Red Hat bulletin RHSB-2026-018, OpenJDK HotSpot source (x86-64 stub generator and CPU feature detection), Oracle Critical Security Patch Update, Qualys, Tenable, CISA alert*

---

### Go/no-go decision checklist

**Before you approve emergency patching:**

- [ ] Backup or snapshot taken (the service's configuration and, for cloud hosts, an image of the current state, with the previous runtime still available so you can go back)
- [ ] Rollback plan written down. A rollback puts the vulnerable runtime back, so give it a time limit and keep the flag on while it lasts
- [ ] Stakeholders told about the maintenance window and the restart
- [ ] Short test plan agreed (the service starts, logins, tokens and SAML flows work, health checks and monitoring agents stay quiet, and Base64-heavy paths aren't noticeably slower if you used the flag)
- [ ] Someone on call during and after the change
- [ ] Restart method confirmed (one node at a time behind the load balancer, a rebuilt image for containers)
- [ ] Right fix confirmed for each platform: the build your own vendor's list names, not a number from a write-up (the .0.3 respins look newer and are vulnerable)
- [ ] Systems you suspect: process list, network connections and logs captured before the restart, and heap dumps and crash logs treated as sensitive

**If you can't tick every box:**

- Add -XX:-UseBASE64Intrinsics to the exposed JVMs and restart them one at a time (the flag needs a restart too, see the QUICK REFERENCE CARD)
- Restrict access to trusted networks where you can. The Canadian Centre advises you to "consider isolating internet-facing applications from public networks until a fix can be applied"
- Take the exposed service offline for now if neither of those is possible

---

## FREQUENTLY ASKED QUESTIONS

### Questions from executives

**Q: How do we know if we're affected?**

**A:** Ask IT four questions. Which Java runtimes do we run, including the copies inside products and container images, and which exact build is each one running right now (the live JVM, not only the file on disk)? Does the machine have an x86-64 processor with AVX-512 VBMI (Intel Xeon Ice Lake-SP, Sapphire Rapids, Emerald Rapids or Granite Rapids, AMD from Zen 4 on)? Are the JVM defaults still on (the Base64 intrinsic is on by default, and so is the C2 compiler in a long-running server)? Does the application pass Base64 from outsiders to the Java decoder (logins, tokens, SAML)? Java 17.0.6 and later, every 18 to 27 release and Oracle's Java 8 Performance Pack contain the code. Standard Java 8, Java 11 and 17.0.0 to 17.0.5 don't, and ARM64 and older Intel servers lack the processor feature. If a vendor or a hosting company runs your Java, ask in writing. The inventory commands are under AM I AFFECTED? SELF-ASSESSMENT.

*Sources: Oracle Critical Security Patch Update, OpenJDK advisory, Red Hat bulletin RHSB-2026-018, OpenJDK HotSpot source*

---

**Q: What's the worst that could happen?**

**A:** It depends on which source you read, and the sources disagree about the top end. In our reading, the most likely harm this week is a crash: VulnCheck says a burst of requests reliably brought a default-configured service down in its testing. Next is a quiet read of the Java heap, which may hold personal data, private keys, secret keys and tokens (Calif calls it JavaBleed). The worst is code execution. Calif says it achieved that before login in Keycloak, Atlassian Jira, Atlassian Confluence, JFrog Artifactory, Jenkins and PingFederate, and after login in Apache Kafka Broker, Apache Solr, Elasticsearch, Gerrit and Spinnaker, all in their default configurations. Calif adds that "The lists are non-exhaustive" and that "there is no universal exploit". It also reports a client-side path: a Java program that opens a TLS connection to a malicious server can be compromised even if it exposes no service of its own. Amazon describes the top end more narrowly: "exploitation could result in a JVM crash for unauthenticated users or, in certain application environments, code execution by an authenticated low-privileged user". The next question covers what has been reproduced.

*Sources: Calif write-up, VulnCheck, Amazon Linux advisory, The Hacker News*

---

**Q: Is anyone exploiting this?**

**A:** Not that anyone has confirmed at the 08:00 UTC cut-off on 18 November. CISA hasn't added the CVE to its exploited list (catalog 2026.11.17), CISA's SSVC entry says Exploitation none, and there is no EPSS score yet. The Canadian Centre says "The Cyber Centre is not aware of active exploitation at this time, but that can change quickly." VulnCheck says it is "not known to be exploited in the wild at time of writing." Tenable, Qualys and Horizon3 report none, and no source names a threat actor, campaign or malware. GreyNoise, at 07:18 UTC, counted "3 IPs Sending Java4Shell-Shaped Base64", "53 Java4Shell-Shaped Requests" and "0 Successful Intrusions". Its tracker has the IPs, and we don't list them here.

Exploit code is where the picture gets more complicated:

- Calif's product chains are private: "The weaponized chains for individual products stay private until everyone has had a chance to upgrade. We will publish them later."
- VulnCheck says a full code-execution exploit has been available to its paying Initial Access Intelligence customers since 23:00 UTC on 17 November, shipped "with a version scanner, a PCAP, and Snort, Suricata, Sigma, and YARA rules"
- Tenable relays a post on X in which Kevin Breen of Immersive says they built a working exploit that "has to be adapted to each application". The post doesn't say it was released
- There is no Metasploit module, and a Nuclei version-check template is proposed but not merged
- 25 GitHub repositories mention the CVE (07:46 UTC). By their descriptions: 12 tools, scanners, detection or mitigation projects, 5 labs or local reproductions, 2 that claim exploits, 2 write-ups and 4 empty. None is verified, and we name none of them. Pentestit's advice: "Read any script before you run it."

Calif and the labs disagree. Calif claims code execution before login in six products. Independent labs have reproduced the overflow, crashes and a memory read, and not code execution. Upwind, on an AWS c6i instance (Intel Ice Lake), saw the overflow corrupt the next object in 97% of rounds and eventually crash the JVM. Blackpoint, per The Hacker News, crashed a test Spring Boot application with about 28,300 malformed login requests over roughly 20 seconds, ran a memory-read test that "worked in all 30 runs", and "did not reproduce remote code execution". Pentestit: "Code execution is still only Calif's claim". Equixly: "Denial of service is the realistic impact." VulnCheck writes "we don't anticipate that CVE-2026-114938 will be easily or widely exploitable", and adds that "adversaries are likely to find narrow but functional paths to RCE in specific applications". watchTowr says it rated the CVE highly likely to be exploited in the wild when it was disclosed. Upwind lists the idea that it is only a crash as a wrong claim, because Calif demonstrated heap disclosure and code execution.

Our reading: crashes are the most likely harm this week, the memory read can be quiet, and code execution needs work tailored to each product. The signs that this has changed would be Calif's release of its chains, a merged Nuclei template, a Metasploit module or a CISA KEV listing. Check again before you rely on any of this.

*Sources: CISA KEV catalog and SSVC entry, FIRST EPSS API, Canadian Centre for Cyber Security alert AL26-029, VulnCheck, Tenable, Qualys, Horizon3, GreyNoise tracker, Calif write-up, Upwind, The Hacker News, Pentestit, Equixly, watchTowr, GitHub repository search for the CVE ID*

---

**Q: The ratings disagree: 8.1, 9.8, 8.8 and 9.2. Which is it?**

**A:** All four are on the record, and each comes from a different scorer with different assumptions. Oracle, the CVE's numbering authority, scores CVSS 3.1 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) and calls it "Difficult to exploit". Red Hat rates it Critical, CVSS 3.0 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), "preliminary and subject to review", with weakness CWE-787. Amazon Linux rates it Important, CVSS 3.1 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). Calif writes "Under CVSS 4.0, this vulnerability scores 9.2 out of 10 (CRITICAL)" and publishes no vector. CISA's alert calls it "This critical memory-corruption vulnerability", and its SSVC entry in the CVE record says Exploitation none, Automatable no, Technical impact total, with weakness CWE-122. NVD shows status "Received", no product data and no score of its own, and displays Oracle's 8.1. Three governments call it critical: the Canadian Centre's AL26-029 is titled "Critical vulnerability impacting Oracle Java", South Korea's intelligence service rated it critical (Korea Times), and Switzerland's BACS calls it a critical vulnerability. NCSC-NL is calmer: medium likelihood, high impact (M/H), because successful exploitation has several requirements.

The spread comes from assumptions. Oracle's 8.1 rests on high attack complexity, Red Hat's 9.8 uses low complexity under CVSS 3.0, and Amazon's 8.8 assumes a logged-in attacker. Our position: CRITICAL for internet-facing Java services on an affected build that run on x86-64 servers with AVX-512 VBMI, with the JVM defaults left on, starting with identity and single sign-on servers, CI and artifact servers, and Jira and Confluence. HIGH for internal services on that hardware, and for Java programs on it that open TLS connections to servers you don't control. Patch first, argue about the label later. RISK DASHBOARD lists every rating.

*Sources: CVE record (Oracle entry and CISA entry), Red Hat CVE page, Amazon Linux advisory, Calif write-up, CISA alert, NVD, Canadian Centre for Cyber Security, Korea Times, Switzerland's BACS, NCSC-NL*

---

**Q: We run on ARM or older Intel. Are we safe?**

**A:** From this bug, yes, today. The vulnerable path needs AVX-512 VBMI, and these don't have it: ARM64 (AWS Graviton, Ampere), Intel Skylake-SP, Cascade Lake and Cooper Lake (AVX-512 without VBMI), Intel Xeon Sierra Forest (no AVX-512), Intel client Alder Lake and later (AVX-512 not supported, so check the flag to be sure) and AMD Zen 3 and older. HotSpot also defaults to UseAVX=2 on early Skylake steppings. Two cautions. Workloads move between machine types, and a hypervisor that masks VBMI removes the path, so the same image can be exposed on one node and safe on the next. Run the CPU check inside each guest, and treat any node pool that contains a VBMI node as exposed (our reading). Take the fixed build in the normal window either way. And the usual rule of thumb runs backwards here (our reading): the newest Java on the newest x86 hardware is exposed, and teams still on older Intel chips or on ARM are clear by accident.

On the clouds, from each provider's own pages. AWS c6i, m6i and r6i (Ice Lake), c7i and m7i (Sapphire Rapids) and c7a and m7a (4th gen AMD EPYC, Zen 4; the VBMI conclusion is inferred from Zen 4) are on VBMI hardware, c5 and m5 (Skylake-SP or Cascade Lake) are not, and Graviton is ARM. Azure Dv5, Dsv5 and Ev5 (Ice Lake, Sapphire Rapids or Emerald Rapids), Dasv6 and Easv6 (AMD EPYC 9004, Genoa) and Dsv6 and Esv6 (Emerald Rapids) all have VBMI. Google Cloud N2 is mixed (VBMI only on its Ice Lake variant, and N2 with 96 or more vCPUs requires Ice Lake), C3, C3D, C4, N4, C4D and N4D have VBMI, and N2D (AMD Milan) has no AVX-512. Red Hat's bulletin names as "most likely" affected: "AWS C6i/M6i/R6i and C7i/M7i/R7a, GCP C3/C3D/C4/C4D/N4/N4D/M3/M4, and Azure Dsv5/Dsv6/Dasv6/Dasv7", plus related D-series v5 to v7 SKUs.

*Sources: Red Hat bulletin RHSB-2026-018, Calif write-up, AWS EC2, Azure and Google Cloud instance documentation, OpenJDK HotSpot source, LLVM and Wikipedia AVX-512 processor tables (our reading where marked)*

---

**Q: We run Java 8 or Java 11. Do we need to do anything?**

**A:** Not for this CVE, but yes for the November updates. Java 11 has no AVX-512 decode intrinsic (only an encode one), and the 2021 change that added the decoder was never backported. Red Hat: "Customers running OpenJDK 8 or OpenJDK 11 are also not affected, as these versions do not contain the vulnerable code path." The OpenJDK advisory marks only the 17, 21, 25 and 27 columns for this CVE. Standard Java 8 is not affected either. The exception is Oracle's Java 8 Performance Pack (8u511b33-perf and earlier), which is affected and fixed in 8u513-perf. Java 17.0.0 to 17.0.5 does not contain the code, because it first shipped in 17.0.6 on 17 January 2023. The reason to update anyway: Oracle's November release has 11 Java SE fixes, and CVE-2026-114941 (7.0, Compiler, Java 21, 25 and 27), CVE-2026-114943 (6.5, Hotspot) and CVE-2026-114946 (4.8, Compiler, every line including 8 and 11) are separate flaws. Oracle's baselines are 1.8.0_513-b04 and 11.0.33.1+4. Don't add the Base64 flag to a Java 8 JVM: Java 8 does not know it and would refuse to start.

*Sources: Red Hat bulletin RHSB-2026-018, OpenJDK advisory, Oracle Critical Security Patch Update, OpenJDK 8 and 11 update source, Oracle 17.0.6 release notes*

---

**Q: Our build ends in .0.3 and looks new. Are we fixed?**

**A:** No. This is the biggest version trap. The October respins ending in .0.2 and .0.3 (17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 and 27.0.1.0.3) look newer than the October releases and are the last vulnerable builds. The fix is the .1 build. Oracle Java SE 17.0.21.1+4, 21.0.13.1+4, 25.0.5.1+4 and 27.0.1.1+4 came out on 17 November 2026, and OpenJDK tagged jdk-17.0.21.1+2, jdk-21.0.13.1+2, jdk-25.0.5.1+2 and jdk-27.0.1.1+4. Other vendors number their builds differently. Corretto adds a fifth field (17.0.21.1.2), Azul Zulu has its own numbers (17.70.201), and some write-ups wrongly cite 17.0.11 and 21.0.3 as fixes (Upwind lists that as a wrong claim). Judge each build by its own vendor's list. The Docker tags add a second trap: Amazon rebuilt its amazoncorretto images on 17 November (23:50 to 23:56 UTC) under their old tag names, so a tag name doesn't prove a fixed image. Check java -version inside the image, or pin by digest.

*Sources: Oracle Critical Security Patch Update and 17.0.21.1 release notes, OpenJDK tags, Corretto, Azul and Docker Hub image tags, Upwind*

---

**Q: Jira, Confluence and Elasticsearch bring their own Java. Does patching our servers fix them?**

**A:** No. The copy of Java a product carries is separate from the server's system Java, and updating one doesn't update the other. Jira's Windows and Linux installers bundle Eclipse Temurin (Jira 11.3.10 and 11.3.11 bundle Temurin 21.0.10_7), and tar.gz installs use your own Java. Confluence's installer bundles Temurin too (Confluence 11.0.1 bundles 25.0.5.8, and 10.2.20 bundles 21.0.13.9). Elasticsearch runs its bundled JDK by default, and its development branch pins 27.0.1.0.3, an affected build. Temurin had not shipped the fix at the cut-off, and we found no statement from Atlassian or Elastic. CISA tells readers to review their inventory for runtimes bundled with third-party applications or included in container images and appliances, because those may not appear as separate entries. What to do: set the flag through each product's own settings today (the technical questions below show where it goes), restart the product, and update when the vendor ships a fixed build or a supported swap of the runtime. JFrog Artifactory is not verified, because its documentation was unreachable.

*Sources: Atlassian bundled Java documentation, Elastic documentation and build files, Adoptium release status, CISA alert*

---

**Q: We run on a managed cloud platform (Google, Heroku, Azure Functions or AWS). Do we need to do anything?**

**A:** It depends on the platform, and the picture is patchy at the cut-off.

- **Google:** bulletin GCP-2026-082 says "As an interim platform safeguard through November 30, 2026, Google has masked AVX-512 VBMI for managed Java 17, 21, and 25 runtimes on the App Engine standard environment and the Cloud Run second generation execution environment (including 2nd gen Cloud Run functions)". It "does not cover the Cloud Run first generation execution environment, Cloud Functions (1st gen), App Engine flexible environment, Cloud Run jobs and worker pools, custom containers, or deployments without automatic base image updates". Update or flag those now, and plan the fix for the rest before the masking ends on 30 November
- **Heroku:** moved its defaults to 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, effective 18 November
- **Azure Functions:** the Java worker starts the JVM with -XX:+TieredCompilation -XX:TieredStopAtLevel=1, so only C1 runs and the default configuration doesn't reach the vulnerable code. Options that turn C2 back on (for example -XX:TieredStopAtLevel=4 or -XX:-TieredCompilation in JAVA_OPTS, languageWorkers__java__arguments or _JAVA_OPTIONS) bring it back. The worker issue checked whether the intrinsic was used and did not test memory corruption, and Microsoft has published no advisory
- **AWS:** Amazon Linux 2 (ALAS2-2026-4123), Amazon Linux 2023 (ALAS2023-2026-3478 to 3481), the Amazon Linux 2027 preview (ALAS2027-2026-371 to 374) and Corretto have fixes, all 17 November. We found no statement on AWS Lambda or Elastic Beanstalk, and none from Azure App Service

Ask the provider in writing which runtime build your workload runs now, and when any fix ships.

*Sources: Google Cloud bulletin GCP-2026-082, Heroku changelog, Azure Functions Java worker issue 909 and Azure Functions Java reference, Amazon Linux advisories, AWS security bulletins and Elastic Beanstalk release notes (no statement found)*

---

**Q: We have a WAF. Does that protect us?**

**A:** Treat it as a layer, not a fix, and don't assume it blocks the bug. AWS WAF's Known Bad Inputs managed rule group, version 1.28, "adds the Java4Shell_BODY, Java4Shell_QUERYARGUMENTS, and Java4Shell_HEADER rules, which protect against CVE-2026-114938". The new rules use the Count action, so they log and don't block until you change the action. Cloudflare's WAF changelog had no Java4Shell entry (newest item 12 November). Inspection limits apply too, per IONIX: "Cloudflare inspects only the first 128 KB of a body", "AWS WAF inspects only the first 8 KB of headers, cookies and body", and Akamai Property Manager rules don't cover the request body. Size limits alone won't stop the bug, because the malformed input that triggers it is short (our reading of Endor Labs' description of the trigger). Calif notes that nginx request buffering frustrates some of its exploit chains, but "Request buffering is not a general mitigation". No network control recovers data already read from memory. CISA advises "restricting and validating Base64 input at the application boundary, enforcing input-size limits, and limiting unauthenticated access", and the Canadian Centre advises you to "consider isolating internet-facing applications from public networks until a fix can be applied". Fix the runtime or set the flag first.

*Sources: AWS WAF managed rules changelog, Cloudflare WAF changelog, IONIX, Endor Labs, Calif write-up, CISA alert, Canadian Centre for Cyber Security alert AL26-029*

---

**Q: Why did we hear about this so late?**

**A:** The problem and the fix approach were public from 9 September 2026, in an OpenJDK pull request, about ten weeks before the release. The fix sat in the Java 27 update repository from 14 October under the bland title "8393212: Base64 optimization improvements", and in the Java 17, 21 and 25 update repositories from 12 November. Oracle reserved the CVE on 22 October. On 17 November the Korea Times reported at 14:26 UTC that South Korea's intelligence service had told public institutions to prepare for a critical Java flaw, and Calif posted at about 16:11 that details had leaked. By Calif's account Oracle and OpenJDK released at 21:00 UTC (some vendors' fixed builds and alerts appeared earlier that evening), the CVE record followed at 21:32, and VulnCheck made a full exploit available to its customers at 23:00. A tool that waits for a CVE record had nothing before 21:32. The full sequence is under ATTACK TIMELINE.

Could you have been hit before the release? In principle, yes, because anyone reading the pull request or the commits could have worked on it. No source reported exploitation at any time up to the cut-off, but no indicators of compromise have been published beyond scanner traffic, so nothing lets you tell either way. If an internet-facing identity, single sign-on, CI or artifact server ran an affected build on VBMI hardware and was neither patched nor flagged after 21:00 UTC on 17 November, rotate its signing keys and stored credentials after patching, and invalidate the sessions and tokens it issued (our reading). For any other affected service, rotate the secrets it held if your logs show the warning signs under DETECTION & FORENSICS at any point since 9 September 2026.

*Sources: OpenJDK update repositories, Oracle Critical Security Patch Update, CVE record, Korea Times, Tenable, VulnCheck, Calif write-up*

---

**Q: How long does patching take, and will it break things?**

**A:** For most services it's a fixed build (or a flag), a restart and some checks. The restart is the cost: the old JVM keeps running the old code until you restart it, whatever is installed on disk, and a single server with no load balancer needs a short window. Behind a load balancer, restart one node at a time and watch the first one. Test that logins, tokens and SAML flows work and that monitoring stays quiet. Containers need a rebuilt image and a redeploy, and products that bundle Java need the vendor's update. Base64-heavy work (tokens, SAML) may slow down with the flag, and nobody has published numbers, so test one node first (our reading). Patch internet-facing services on VBMI hardware first, with identity and single sign-on servers, CI and artifact servers, and Jira and Confluence at the head of the line, then roll out.

*Sources: Oracle Critical Security Patch Update, Red Hat bulletin RHSB-2026-018, Docker Hub image tags*

---

**Q: Should we tell our customers?**

**A:**

- If you patch and find no sign of compromise, this is routine maintenance, and usually no notification is needed.
- If you find indicators of compromise, or have reason to think secrets were read from a first-tier server, talk to legal straight away. GDPR, NIS2, CERT-In, HIPAA, SEC and US state laws may all apply, some with deadlines measured in hours.

---

**Q: Should we pay for outside help?**

**A:** Yes if you see any sign of compromise, run many internet-facing Java services across many teams, work in a regulated industry, or depend on products that bundle Java and have no vendor fix yet. Probably not if you have a handful of services on vendors that already ship the fix and a team that can patch and restart today.

---

### Questions from technical teams

**Q: How do we check whether a live JVM is exposed?**

**A:** A JVM is exposed only when all four of these hold: (1) an affected HotSpot build, (2) an x86-64 CPU with AVX-512 VBMI and BW visible to the JVM, with UseAVX at 3, which is the default on those CPUs, (3) the Base64 intrinsic on (the default) and the C2 compiler running, which is the default for long-running servers, and (4) an application that passes attacker-supplied Base64 to the basic or URL-safe decoder. In the HotSpot source the stub tests supports_avx512_vbmi() and supports_avx512bw(), and Java 17 also needs avx512vl before it turns the intrinsic on by default. bmi2 is not a gate, so Calif's four-flag check (avx512f, avx512bw, avx512vbmi, bmi2) asks for more than it needs but gives no wrong answer on real hardware. Only C2 inlines the stub, and C1 does not. The MIME decoder skips the vector path (Endor Labs says it is "Not affected"). The basic and URL-safe decoders (Base64.getDecoder() and Base64.getUrlDecoder()) are the ones that reach it after C2 has compiled the decode path. Red Hat names typical carriers: HTTP Basic credentials, SAML artifacts, CSRF tokens and MIME encoded words.

```bash
# Running JVMs on this host (run as root to see every user's JVMs). JVMs inside containers don't show here: run it inside each container
jcmd -l
# The live version of one JVM (run as the JVM's user or root)
jcmd <pid> VM.version
# Is the vulnerable path switched on in that JVM?
jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
# Does this machine, or this VM guest, have AVX-512 VBMI? Prints avx512vbmi if it does
grep -o -w avx512vbmi /proc/cpuinfo | head -1
# Kubernetes with Node Feature Discovery: the nodes that have AVX-512 VBMI
kubectl get nodes -l feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI=true
```

Read the output: exposed means UseAVX is 3 and UseBASE64Intrinsics is true, on a VBMI CPU, with C2 running. Not exposed means UseBASE64Intrinsics is false, or UseAVX is 2 or lower, or TieredStopAtLevel is 1. lscpu output containing "avx512" is not enough, because Skylake-SP and Cascade Lake print AVX-512 flags without VBMI (the Canadian Centre's lscpu | grep avx512 over-reports). Root sees every user's JVMs, and jcmd needs the JVM's own user or root. The full set of inventory commands is under AM I AFFECTED? SELF-ASSESSMENT.

*Sources: Red Hat bulletin RHSB-2026-018, OpenJDK HotSpot source (x86-64 stub generator, CPU feature detection and C1 compiler), Endor Labs, Calif write-up, Canadian Centre for Cyber Security alert AL26-029, OpenJDK jcmd documentation*

---

**Q: Which flag should we use, and does it slow us down?**

**A:** Preferred: start each affected JVM with -XX:-UseBASE64Intrinsics, then restart. Red Hat: it "disables the hardware-accelerated Base64 implementation only. This is the preferred option, as it removes the vulnerable code path while leaving other AVX-512 optimizations in place." Calif recommends it too. It is a regular product flag in Java 11 and later on both x86-64 and ARM64. Java 8 does not know it and would refuse to start. The alternative is -XX:UseAVX=2, which turns off all AVX-512 code in the JVM. It is x86-64 only: an ARM64 JVM won't start with it. The Canadian Centre and Google recommend it, and Google's form for mixed fleets adds -XX:+IgnoreUnrecognizedVMOptions, set in JDK_JAVA_OPTIONS, which only the java launcher reads.

Both need a restart. Base64-heavy work (tokens, SAML) may slow down. Nobody has published numbers, so test one node first (our reading). Know the limits:

- It closes this bug only. The other November fixes stay open until you update
- It protects only the JVMs that actually received it, so confirm each live JVM with jcmd after the restart
- Remove it once the fixed runtime is confirmed (Red Hat, Google)

```bash
# Preferred stopgap through the JVM's own variable. Add it to the service's environment, keeping any value already there, then restart the service
JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
# Google's form for fleets that mix x86-64 and ARM64 (read by the java launcher only)
JDK_JAVA_OPTIONS="-XX:+IgnoreUnrecognizedVMOptions -XX:UseAVX=2"
```

*Sources: Red Hat bulletin RHSB-2026-018, Calif write-up, Canadian Centre for Cyber Security alert AL26-029, Google Cloud bulletin GCP-2026-082, OpenJDK HotSpot flag definitions for Java 8 and 17, Oracle java launcher documentation*

---

**Q: Where does the flag go? We run Jira, Confluence, Elasticsearch, Keycloak, Jenkins or PingFederate.**

**A:** Where the flag goes decides whether it works. JAVA_TOOL_OPTIONS is read by the JVM itself (it prints "Picked up JAVA_TOOL_OPTIONS") and reaches custom launchers. HotSpot skips it only when the process has special privileges, such as a setuid launch. JDK_JAVA_OPTIONS is read only by the java launcher. Products with their own launchers need the flag in their own configuration. Add the flag to what is already there, then restart:

```bash
# Jira: <jira-install>/bin/setenv.sh
JVM_SUPPORT_RECOMMENDED_ARGS="-XX:-UseBASE64Intrinsics"
# Confluence: <installation-directory>/bin/setenv.sh, keeping ${CATALINA_OPTS} in place
CATALINA_OPTS="-XX:-UseBASE64Intrinsics ${CATALINA_OPTS}"
# Keycloak: use JAVA_OPTS_APPEND, never JAVA_OPTS
JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics"
# Jenkins container
JENKINS_JAVA_OPTS="-XX:-UseBASE64Intrinsics"
# Tomcat: $CATALINA_BASE/bin/setenv.sh
CATALINA_OPTS="$CATALINA_OPTS -XX:-UseBASE64Intrinsics"
# Kafka
KAFKA_OPTS="-XX:-UseBASE64Intrinsics"
```

```text
# Elasticsearch: a file such as config/jvm.options.d/java4shell.options containing this one line
-XX:-UseBASE64Intrinsics
# PingFederate: add this line to pingfederate/bin/jvm-memory.options
-XX:-UseBASE64Intrinsics
```

Two traps catch people:

- **Elasticsearch** strips JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS ("warning: ignoring ...; pass JVM parameters via ES_JAVA_OPTS"), so setting them does nothing. Put the flag in a file under config/jvm.options.d/ (Debian and RPM: /etc/elasticsearch/jvm.options.d/, Docker: a bind mount into /usr/share/elasticsearch/config/jvm.options.d/)
- **Keycloak** replaces all of its own defaults when you set JAVA_OPTS ("JAVA_OPTS already set in environment; overriding default settings"). Add flags with JAVA_OPTS_APPEND

Other products: Jira reads JVM_SUPPORT_RECOMMENDED_ARGS in bin/setenv.sh (in Docker, the variable of the same name). Confluence reads CATALINA_OPTS in bin/setenv.sh, and the existing ${CATALINA_OPTS} must stay in place. The Jenkins container reads JENKINS_JAVA_OPTS (or JAVA_OPTS), and Jenkins package installs use a systemd override. PingFederate reads pingfederate/bin/jvm-memory.options, and its zip install uses a Java you install yourself. Tomcat and Kafka tarball installs use the system Java, with options in bin/setenv.sh (CATALINA_OPTS) and KAFKA_OPTS, and their official container images are built on eclipse-temurin. JFrog Artifactory is not verified, because its documentation was unreachable.

```bash
# After the restart, confirm the running JVM picked it up (run as the JVM's user or root)
jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
```

*Sources: Atlassian Jira and Confluence documentation, Elastic documentation and launcher script, Keycloak launcher script, Jenkins container documentation and Jenkins systemd documentation, Ping Identity documentation, Apache Tomcat and Kafka scripts, Oracle java launcher documentation, OpenJDK HotSpot source*

---

**Q: I installed the fixed runtime. Do I still need to restart?**

**A:** Yes, every JVM that used the old runtime. A runtime on disk doesn't fix a JVM that is still running, and after an in-place upgrade a running JVM still runs the old code. A release file describes the runtime on disk, so trust jcmd on the live process. First compare the full version string with your own vendor's list of fixed builds (the .0.3 question above covers the numbering traps), then confirm that the live JVM reports it. The commands are in the verification block under SUCCESS CRITERIA & VERIFICATION.

*Sources: Oracle Critical Security Patch Update, OpenJDK jcmd documentation, vendor release notes*

---

**Q: What about Docker images, containers and Kubernetes?**

**A:** A container runs the Java inside its image, so patching the host changes nothing, and jcmd -l on the host doesn't list JVMs inside containers. Rebuild the image on a fixed base and redeploy:

```dockerfile
# Docker: rebuild your image on a fixed base, then redeploy. Pin the digest after you have checked it
FROM amazoncorretto:21
```

```bash
# After the restart, confirm each live JVM runs the fixed build (run as the JVM's user or root)
jcmd <pid> VM.version
# Container images: the version inside the image, not the tag name
docker exec <container> java -version
```

The image facts at the cut-off:

- Amazon rebuilt its amazoncorretto images on 17 November (23:50 to 23:56 UTC) under their old tag names (for example 17.0.21-alpine3.24), so a tag name doesn't prove a fixed image. Check the version inside it, or pin by digest
- Images built on Temurin wait for Adoptium. The eclipse-temurin images' newest GA is still 17.0.21+9, 21.0.13+9 and 25.0.5+8, and Adoptium's release-status issue 326 shows testing in progress. That holds back the official Jenkins, Tomcat and Kafka images
- The official Keycloak image uses the UBI 9 java-21-openjdk-headless package, so its fix follows Red Hat's errata, and Red Hat had none at the cut-off
- The Paketo azul-zulu buildpack merged the fix on 18 November (releases 11.8.3 and 11.8.4)

Until your base image is fixed, set the flag in the container's environment (JAVA_TOOL_OPTIONS, or the product's own variable from the question above) and redeploy. On Kubernetes, the same image can be exposed on one node and safe on the next, because a hypervisor that masks VBMI removes the path. Treat any node pool that contains a VBMI node as exposed (our reading), and use the node-feature check in the first technical question. Retire golden images, VM templates and autoscaling launch configurations that still carry an affected runtime.

*Sources: Docker Hub image tags, Adoptium release status, Jenkins, Tomcat, Kafka and Keycloak container build files, Paketo buildpack releases, OpenJDK HotSpot source*

---

**Q: Our scanner is silent, or it flags a build we know is patched. Can we trust it?**

**A:** Read both results with care. Coverage at the cut-off:

- **Qualys:** QID 389494, plus 389610 for Oracle Java SE and 389608 for Corretto
- **Tenable:** plugins 382091 ("Oracle Java SE Oracle CSPU Nov 2026 (Java4Shell)") and 382045 (Corretto 17)
- **Rapid7:** an authenticated check in its 17 November content release
- **Snyk:** lists RHEL 10 and CentOS 10 packages and the Conan openjdk package
- **Fortinet:** Threat Signal 6668, with endpoint vulnerability signatures for Oracle Java. It says "FortiGuard IPS detection opportunities for crafted Base64 input through network inspection are under investigation"
- **Snort community rules:** "SERVER-WEBAPP OpenJDK Base64 decoder remote code execution attempt". Snort 2 has 12 rules (SIDs 67502 to 67513, 8 commented out by default) and Snort 3 has 13 (SIDs 67502 to 67513 and 301754). They key on specific carriers (a SAML artifact, a connector authorization header, a Jenkins header and MIME encoded words)
- **AWS WAF:** Known Bad Inputs 1.28, in Count mode
- **Not found:** nothing yet from Emerging Threats Open (last build 17 November, 21:59 UTC), Sigma or Cloudflare. Elastic has a community rule proposal only (issue 7199), VulnCheck's rules are for its customers, and a Nuclei version-check template is proposed but not merged

NVD has no product data, so tools that read NVD alone miss the CVE, and the Ubuntu, SUSE and Alpine feeds had no entry. A version scanner can't see the CPU or the JVM flags, and a dependency scanner can't see the runtime. So a clean result can't prove you're fine, and a hit on a patched build may be a numbering mismatch. Semgrep: "A WAF rule, a lack of alerts or a lack of crashes does not prove that a runtime is patched or that no attempt occurred." Judge by your vendor's list and by jcmd on the live JVM.

*Sources: Qualys, Tenable, Rapid7, Snyk, Fortinet, Snort community rules, AWS WAF managed rules changelog, Emerging Threats and Elastic issue trackers, Nuclei pull requests, NVD, Semgrep*

---

**Q: Should we run Calif's self-test?**

**A:** Not on production. Calif publishes a bounded self-test that prints REPRODUCED on an affected JDK and processor. It tests the JDK and CPU it runs on, not whether an application is reachable. It is code you didn't write, and it is meant to reproduce the bug on the machine it runs on, so read it first and run it only in an isolated lab VM with no route to production, never as root. The read-only checks in the first technical question tell you whether a host is exposed without running anything that touches the bug. Pentestit's advice applies to every script you find: "Read any script before you run it." We name no repositories and link none of them.

*Sources: Calif write-up, Pentestit, GitHub repository search for the CVE ID (names withheld)*

---

**Q: What about developer laptops and desktops?**

**A:** Some are exposed. Intel client chips from the Ice Lake, Tiger Lake and Rocket Lake generations have AVX-512 VBMI, so a laptop or desktop with one of them that runs an affected Java 17, 21, 25 or 27 has the vulnerable path on. Intel client Alder Lake and later don't support AVX-512 (check the flag to be sure). The /proc/cpuinfo check below works on Linux. On other systems, look the processor model up against the lists in this document, or read UseAVX in the JVM's own flags with jcmd (3 means AVX-512 is on for that JVM, 2 or lower means it is off). Then update the toolchain and restart whatever Java the machine runs.

```bash
# Does this machine have AVX-512 VBMI? Prints avx512vbmi if it does (Linux)
grep -o -w avx512vbmi /proc/cpuinfo | head -1
# Homebrew, for each formula you use
brew update && brew upgrade openjdk@21
```

Homebrew has openjdk 27.0.1.1, openjdk@17 17.0.21.1, openjdk@21 21.0.13.1 and openjdk@25 25.0.5.1. Arch Linux has jdk17-openjdk 17.0.21.1.u2-1, jdk21-openjdk 21.0.13.1.u2-1, jdk25-openjdk 25.0.5.1.u2-1 and jdk-openjdk 27.0.1.1.u4-1 (built 17 November). The client-side variant in the next question applies to any machine that runs a Java program and opens TLS connections to servers it doesn't control.

*Sources: Red Hat bulletin RHSB-2026-018, Calif write-up, Wikipedia and LLVM AVX-512 processor tables, Homebrew formulae, Arch Linux packages*

---

**Q: Our Java programs only make outbound TLS connections and expose no service. Are they in scope?**

**A:** Possibly, and this is the least understood path. Calif: "samczsun also shared a client-side exploit with us. A Java program that opens a TLS connection to a malicious server can be compromised, even if it exposes no service of its own." No source says how that path works, and no source has said whether decode(ByteBuffer) or wrap(InputStream) reach the stub or what the C2 compile threshold is. Our position: HIGH for Java programs on VBMI hardware that open TLS connections to servers you don't control, and a normal-window update elsewhere. The fixes are the same: a fixed build, or the flag until you have one. Because the bad data would come from the far end of a connection you opened, a WAF or a request-size limit in front of your own services doesn't sit in that path (our reading), and nobody has published a detection signal for it. Start with the programs that reach furthest outside your network.

*Sources: Calif write-up, Red Hat bulletin RHSB-2026-018*

---

**Q: What about IBM Semeru (OpenJ9) and GraalVM Native Image?**

**A:** Both are open questions, and they differ.

- **IBM Semeru (OpenJ9):** contested. Red Hat's VEX file lists java-21-ibm-semeru-certified-jdk on RHEL 10 as known affected, while IBM has made no statement and OpenJ9 issue 25216 is open with no reply. We found no source on whether OpenJ9 accepts the HotSpot flags, so test the flag on one node before you roll it out, and ask IBM in writing
- **GraalVM Native Image:** probably not affected, because native executables don't run HotSpot's C2 compiler (inferred). No vendor has said so. Oracle lists its GraalVM builds on the JVM as affected: GraalVM for JDK 17.0.21.0.3 and 21.0.13.0.3, and Enterprise Edition 21.3.20.0.3, with fixes in 17.0.21.1, 21.0.13.1, 25.0.5.1 and Enterprise Edition 21.3.20.1. GraalVM Community's newest release (3 November) is built on the affected 25.0.5.0.3

*Sources: Red Hat VEX file, OpenJ9 issue tracker, Oracle Critical Security Patch Update, Oracle GraalVM release notes, GraalVM Community releases*

---

**Q: Is the fix complete?**

**A:** For this bug, the shipped .1 builds are the fix, and no incomplete fix has been reported. Oracle credits Albert Yang, and Quang Luong of Calif.io. The fix is identical in the 17, 21, 25 and 27 update repositories: four lines added to src/hotspot/cpu/x86/stubGenerator_x86_64.cpp that hand a padded tail shorter than one block back to Java. The commit title is "8393212: Base64 optimization improvements". The mainline (development) fix is still not visible in public repositories. This analysis has no independent test of the fix to report. Three things nobody has said yet: whether decode(ByteBuffer) or wrap(InputStream) reach the stub, the C2 compile threshold, and how the client-side path works.

The code has history. JDK-8268276 added the AVX-512 decoder to mainline on 25 June 2021, and a crash fix for it landed on 12 December 2021 (JDK-8273108). It was backported to the 17 updates on 9 November 2022 and first shipped in 17.0.6 on 17 January 2023. So keep Java on a regular update cycle. Oracle's November release carries 11 Java SE fixes, and Oracle's 17.0.21.1 notes say it is not recommended to use that build after the 19 January 2027 quarterly update.

*Sources: OpenJDK update repositories (fix commit and patch), Oracle Critical Security Patch Update and 17.0.21.1 release notes, OpenJDK mainline history, CVE record*

---

## SUCCESS CRITERIA & VERIFICATION

### You have successfully responded when:

**Technical validation checklist:**

- [ ] **All Java runtimes inventoried:**
    - Hosts, VMs, container images and running containers, copies bundled inside products (Jira, Confluence, Elasticsearch and others), and appliances
    - Vendor, full version string, whether the CPU has AVX-512 VBMI, whether the service is internet facing, and the JVM flags recorded for each
- [ ] **All exposed JVMs fixed or flagged:**
    - Running a fixed build (17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 or your vendor's equivalent, checked against that vendor's own list)
    - Where the vendor has no fix yet: the flag on, confirmed with jcmd, and a dated task to update the day the fix ships
    - Retired Java lines (18 to 20, 22 to 24 and 26) moved to 21.0.13.1, 25.0.5.1 or 27.0.1.1
    - Products that bundle Java: the vendor's answer in writing, and the flag set through the product's own settings until the fix ships
- [ ] **All updated JVMs restarted:** every live JVM started after the fixed runtime was installed, and container images rebuilt and redeployed
- [ ] **Verification passes:**

    ```bash
    # Running JVMs on this host (run as root to see every user's JVMs). JVMs inside containers don't show here: run it inside each container
    jcmd -l
    # The live version of one JVM (run as the JVM's user or root)
    jcmd <pid> VM.version
    # Is the vulnerable path switched on in that JVM?
    jcmd <pid> VM.flags -all | grep -E 'UseAVX|UseBASE64Intrinsics|TieredStopAtLevel|TieredCompilation'
    # Does this machine, or this VM guest, have AVX-512 VBMI? Prints avx512vbmi if it does
    grep -o -w avx512vbmi /proc/cpuinfo | head -1
    # Kubernetes with Node Feature Discovery: the nodes that have AVX-512 VBMI
    kubectl get nodes -l feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI=true
    # Container images: the version inside the image, not the tag name
    docker exec <container> java -version
    # Java runtimes on disk, including bundled ones (run as root). Compare the full version string
    find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name release -exec grep -H -E '^(IMPLEMENTOR|JAVA_RUNTIME_VERSION|JAVA_VERSION)=' {} + 2>/dev/null
    # Distribution packages (they don't show bundled or tarball runtimes)
    dpkg -l 'openjdk-*'
    rpm -qa 'java-*openjdk*'
    # JVM crash logs written since 9 September 2026, then the ones with the Base64 decoder in them (run as root)
    find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name 'hs_err_pid*.log' -newermt '2026-09-09' -print 2>/dev/null
    find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -name 'hs_err_pid*.log' -newermt '2026-09-09' -exec grep -l 'Base64\$Decoder' {} + 2>/dev/null
    ```

- [ ] **No indicators of compromise** (see the checklist under DETECTION & FORENSICS)
- [ ] **Secrets handled:**
    - First tier (an internet-facing identity, single sign-on, CI or artifact server on an affected build and VBMI hardware, unpatched and unflagged after 21:00 UTC on 17 November 2026): signing keys and stored credentials rotated after patching, and the sessions and tokens it issued invalidated
    - Second tier (any other affected service): secrets rotated where your logs show the warning signs at any point since 9 September 2026
- [ ] **Defense in depth:**
    - [ ] Alerts on JVM crash logs (hs_err_pid files) and on container restart counts
    - [ ] Alerts on Java processes starting shells or download tools, and on new outbound connections from Java processes (build servers start shells legitimately, so tune for them)
    - [ ] The WAF rule action chosen on purpose (the Java4Shell rules in AWS WAF Known Bad Inputs 1.28 ship in Count mode), and recorded as a layer, not a fix
    - [ ] Log retention extended for forensics
    - [ ] Golden images, VM templates and autoscaling launch configurations that carried an affected runtime retired

---

**Operational validation checklist:**

- [ ] **Services work:** logins, tokens and SAML flows, health checks, backups and monitoring agents tested after the restart
- [ ] **No new crashes, restart loops or latency spikes** after the restart or the flag (Base64-heavy paths may be slower with the flag)
- [ ] **Stopgaps cleaned up:** the flag removed once the fixed runtime is confirmed, or kept on purpose with a date, and WAF actions set on purpose
- [ ] **Documentation done:** timeline, versions before and after, flags in force, restart times
- [ ] **Stakeholders updated:**
    - [ ] Leadership briefed
    - [ ] Legal told whether any compromise was found
    - [ ] Insurer told the remediation is complete

---

**Compliance validation checklist:**

- [ ] **Audit trail kept:** every action timestamped, every decision explained
- [ ] **Evidence preserved** where there was any doubt (heap dumps and crash logs stored securely, because they hold secrets)
- [ ] **Breach decision documented:** legal agrees on whether notification is needed, and the evidence supports that conclusion
- [ ] **Deadlines tracked:** the BOD 26-04 clocks for US federal agencies, and PCI DSS requirement 6.3.3 (about 17 December 2026 by our reading)

---

### Post-incident review checklist

**Hold within a week of finishing:**

- [ ] **What went well:**
    - Time from the 17 November release to a verified fix or flag
    - How fast you found every Java runtime
- [ ] **What needs work:**
    - Gaps in the inventory (bundled runtimes, container images, golden images, vendor products that carry Java)
    - Restart procedures and maintenance windows
    - How many products waited on a vendor with no fix
    - Contacts at product vendors and cloud providers
- [ ] **Metrics captured:**
    - Time to inventory: [X hours from the day you learned of it]
    - Time to patch or flag: [X hours]
    - Time to verified restart: [X hours]
    - Systems affected: [X]
    - Staff hours: [X]
- [ ] **Actions:**
    - Keep the Java inventory current, with the build, the flags and the CPU feature for each runtime
    - Add live-JVM verification (jcmd VM.version) to the patch process
    - Rebuild images on a schedule instead of waiting for an advisory
    - Retire Java lines that get no fixes
    - Plan for 30 November 2026 (Google's CPU-feature masking ends), 15 December 2026 (Oracle's next Critical Security Patch Update) and 19 January 2027 (Oracle's next quarterly Critical Patch Update)

---

## ADDITIONAL RESOURCES

### Official security advisories

- **Oracle Critical Security Patch Update (November 2026):** https://www.oracle.com/security-alerts/cspunov2026.html (released 17 November 2026; CVE-2026-114938, component Compiler, CVSS 3.1 8.1; affects Oracle Java SE 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 and 27.0.1.0.3, Oracle GraalVM for JDK 17.0.21.0.3 and 21.0.13.0.3, and Oracle GraalVM Enterprise Edition 21.3.20.0.3)
- **Oracle security alerts:** https://www.oracle.com/security-alerts/ (the next Critical Security Patch Update is 15 December 2026, and the next quarterly Critical Patch Update is 19 January 2027)
- **OpenJDK vulnerability advisory:** https://openjdk.org/groups/vulnerability/advisories/2026-11-17 (marks the 17, 21, 25 and 27 columns for this CVE and leaves 8 and 11 empty; it lists no fixed builds. The fixed tags in the update repositories are jdk-17.0.21.1+2, jdk-21.0.13.1+2, jdk-25.0.5.1+2 and jdk-27.0.1.1+4)
- **CVE record:** https://www.cve.org/CVERecord?id=CVE-2026-114938 (published 17 November 2026, 21:32 UTC; CISA's entry adds the SSVC result)
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2026-114938 (received 17 November 2026, 22:18 UTC; status "Received", no CPE data and no NVD score, shows Oracle's 8.1)
- **CISA KEV catalog:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog (the CVE is not listed, catalog 2026.11.17)
- **EPSS:** https://api.first.org/data/v1/epss?cve=CVE-2026-114938 (no score yet at the cut-off)
- **Fix commit (Java 17 update repository):** https://github.com/openjdk/jdk17u/commit/8ea73158afc9f2c62f72df68beb8723032bf695e ("8393212: Base64 optimization improvements"; the mainline fix is still not visible in public repositories)
- **Oracle release notes for the fixed builds:** 17.0.21.1 https://www.oracle.com/java/technologies/javase/17-0-21-1-relnotes.html, 21.0.13.1 https://www.oracle.com/java/technologies/javase/21-0-13-1-relnotes.html, 25.0.5.1 https://www.oracle.com/java/technologies/javase/25-0-5-1-relnotes.html, 27.0.1.1 https://www.oracle.com/java/technologies/javase/27-0-1-1-relnotes.html and the Java 8 Performance Pack 8u513-perf https://www.oracle.com/java/technologies/javase/8u513-perf-relnotes.html (the 17.0.21.1 notes say it is not recommended to use that build after the 19 January 2027 quarterly update)

### Java vendors and distributions

Status at 07:59 UTC on 18 November 2026.

- **Red Hat bulletin RHSB-2026-018:** https://access.redhat.com/security/vulnerabilities/RHSB-2026-018 (status "Ongoing"; the preferred flag, the exposure test and the cloud families it names as most likely affected)
- **Red Hat CVE page:** https://access.redhat.com/security/cve/cve-2026-114938 (Critical, CVSS 3.0 9.8, "preliminary and subject to review", CWE-787; no errata yet)
- **Red Hat VEX file:** https://access.redhat.com/security/data/csaf/v2/vex/2026/cve-2026-114938.json (revision 3 lists 138 products as known affected: RHEL 8 java-17 and java-21-openjdk, RHEL 9 java-17, -21 and -25-openjdk, RHEL 10 java-21 and java-25-openjdk plus java-21-ibm-semeru-certified-jdk, and Red Hat build of OpenJDK 17, 21 and 25; Hardened Images (hi/openjdk) is "Fix deferred")
- **Amazon Linux:** https://explore.alas.aws.amazon.com/CVE-2026-114938.html (Important, CVSS 3.1 8.8; Amazon Linux 2 ALAS2-2026-4123 with java-17-amazon-corretto 17.0.21.1.2, Amazon Linux 2023 ALAS2023-2026-3478 to 3481, Amazon Linux 2027 preview ALAS2027-2026-371 to 374, all 17 November 2026; the 22, 23, 24 and 26 packages are "No Fix Planned")
- **Amazon Corretto:** https://github.com/corretto/corretto-17/releases (Corretto 17 releases. The matching 21, 25 and 27 repositories carry 21.0.13.1.2, 25.0.5.1.2 and 27.0.1.1.4. All four went up on 17 November 2026, 19:49 to 20:06 UTC)
- **Amazon Corretto Docker images:** https://hub.docker.com/_/amazoncorretto (rebuilt 17 November 2026, 23:50 to 23:56 UTC, under their old tag names)
- **Azul Zulu:** https://docs.azul.com/core/cve (17.70.201, 21.54.201, 25.38.201 and 27.30.201, and the security-only stream 17.69.204, 21.53.202 and 25.37.202, 17 November 2026)
- **SAP SapMachine:** https://github.com/SAP/SapMachine/releases (17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, 17 November 2026)
- **Eclipse Temurin:** https://github.com/adoptium/temurin/issues/326 (release status, testing in progress) and https://hub.docker.com/_/eclipse-temurin (newest GA still 17.0.21+9, 21.0.13+9 and 25.0.5+8, not fixed)
- **Microsoft Build of OpenJDK:** https://learn.microsoft.com/en-us/java/openjdk/release-notes (newest builds 17.0.21.0.2, 21.0.13.0.2 and 25.0.5.0.2, not fixed)
- **BellSoft Liberica:** https://github.com/bell-sw/Liberica/releases (newest builds are the affected .0.3 releases)
- **Debian:** https://security-tracker.debian.org/tracker/CVE-2026-114938 (openjdk-17, -21, -25 and -27 unfixed in bookworm, trixie, forky and sid)
- **GraalVM Community:** https://github.com/graalvm/graalvm-ce-builds/releases (the newest release, 3 November 2026, is built on the affected 25.0.5.0.3)
- **Arch Linux:** https://archlinux.org/packages/extra/x86_64/jdk21-openjdk/ (jdk21-openjdk 21.0.13.1.u2-1. The matching packages are jdk17-openjdk 17.0.21.1.u2-1, jdk25-openjdk 25.0.5.1.u2-1 and jdk-openjdk 27.0.1.1.u4-1, all built 17 November 2026)
- **Homebrew:** https://formulae.brew.sh/formula/openjdk@21 (openjdk@21 21.0.13.1. The matching formulae are openjdk 27.0.1.1, openjdk@17 17.0.21.1 and openjdk@25 25.0.5.1)
- **No fix or advisory yet:** Ubuntu (no CVE entry), SUSE (no CVE page), Alpine (edge still ships the .0.3 builds), Oracle Linux, Rocky Linux and AlmaLinux (no advisory). Fedora was not checked (bot challenge). IBM Semeru: no statement, and OpenJ9 issue 25216 is open with no reply

### Government and CERT advisories

- **CISA alert:** https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching (17 November 2026; "This critical memory-corruption vulnerability"; advises restricting and validating Base64 input at the application boundary, enforcing input-size limits, and limiting unauthenticated access)
- **CISA BOD 26-04:** https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk (10 June 2026; revoked BOD 22-01; the KEV timelines apply now)
- **Canadian Centre for Cyber Security:** AL26-029, "Critical vulnerability impacting Oracle Java" (17 November 2026, 20:27 UTC), https://www.cyber.gc.ca/en/alerts-advisories/al26-029-critical-vulnerability-impacting-oracle-java-cve-2026-114938 (recommends -XX:UseAVX=2)
- **Switzerland, BACS:** https://www.bacs.admin.ch/en/warnung-java-2-en (18 November 2026, 06:33 to 06:41 UTC; calls it a critical vulnerability)
- **NCSC-NL:** NCSC-2026-0495 (17 November 2026, 21:55 UTC), medium likelihood and high impact (M/H): https://advisories.ncsc.nl/advisory?id=NCSC-2026-0495
- **South Korea:** the Korea Times reported at 14:26 UTC on 17 November 2026 that the National Intelligence Service had told public institutions to prepare for a critical Java flaw: https://www.koreatimes.co.kr/southkorea/society/20261117/seouls-spy-agency-issues-cybersecurity-advisory-for-flaws-found-in-programming-language-java. The science ministry and KISA advise urgent inspection and updates, and the presidential office held an emergency meeting (no links listed here)

### Research and threat intelligence

- **Calif write-up:** https://calif.io/java4shell/ (the CVSS 4.0 score of 9.2, the product claims, JavaBleed, the client-side path and the bounded self-test)
- **GreyNoise tracker:** https://java4shell.events.greynoise.io/ (at 07:18 UTC on 18 November 2026: 3 IPs, 53 requests, 0 successful intrusions)
- **VulnCheck:** https://www.vulncheck.com/blog/java4shell (a full exploit for its paying Initial Access Intelligence customers since 23:00 UTC on 17 November 2026)
- **Upwind:** https://www.upwind.io/blog/java4shell-what-we-know-now-and-what-comes-next (reproduced the overflow on an AWS c6i instance; lists wrong claims)
- **The Hacker News:** https://thehackernews.com/2026/11/java4shell-cve-2026-114938-enables-pre.html (Blackpoint's crash and memory-read tests; "other labs have so far reproduced crashes and a memory leak but not the code execution")
- **Tenable FAQ:** https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability (relays Calif's post and Kevin Breen's post on X)
- **Qualys:** https://blog.qualys.com/vulnerabilities-threat-research/2026/11/17/how-to-find-mitigate-and-patch-the-critical-java4shell-flaw-cve-2026-114938-now
- **Rapid7:** https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17/ (17 November 2026, 18:33 UTC)
- **Endor Labs:** https://www.endorlabs.com/learn/java4shell-unauthenticated-rce-reported-in-openjdk-17-cve-2026-114938 (the MIME decoder is "Not affected"; the crash signature)
- **Semgrep:** https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability/
- **Prophet Security:** https://www.prophetsecurity.ai/blog/java4shell
- **Threat Defence:** https://threatdefence.com/article/java4shell-cve-2026-114938-openjdk-rce-patching-hunting
- **IONIX:** https://www.ionix.io/blog/java4shell-cve-2026-114938-and-how-ionix-can-help/ (WAF inspection limits)
- **Pentestit:** https://pentestit.com/java4shell-cve-2026-114938-detection-mitigation/ ("Code execution is still only Calif's claim")
- **watchTowr:** https://watchtowr.com/intelligence/java4shell-cve-2026-114938-faq/ (FAQ published 17 November 2026, 16:23 UTC)
- **Equixly:** https://equixly.com/blog/2026/11/17/cve-2026-114938-pre-auth-heap-overflow-in-java-17-21-and-25/ ("Denial of service is the realistic impact.")
- **Scale:** nobody has published an internet-wide count, and version banners say nothing about the CPU. Reuters (cited by name only), citing a government survey, puts Java's share of programming-language use for South Korea's public-sector information systems at 72%. That is a share of language use, not of systems, and it is not evidence of attacks

### Detection and scanning tools

- **Checkers:** this analysis has no checker script. Use the read-only commands under AM I AFFECTED? SELF-ASSESSMENT and DETECTION & FORENSICS
- **Exploit tracking:** EPSS has no score yet, CISA KEV does not list the CVE (catalog 2026.11.17), there is no Metasploit module, and a Nuclei version-check template is proposed but not merged
- **AWS WAF:** https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html (Known Bad Inputs 1.28 adds the Java4Shell_BODY, Java4Shell_QUERYARGUMENTS and Java4Shell_HEADER rules, in Count mode)
- **Snort community rules:** https://www.snort.org/downloads/community/snort3-community-rules.tar.gz (the Snort 3 archive: 13 rules, SIDs 67502 to 67513 and 301754, "SERVER-WEBAPP OpenJDK Base64 decoder remote code execution attempt". The separate Snort 2 archive has 12 rules, SIDs 67502 to 67513, 8 commented out by default)
- **Fortinet:** https://www.fortiguard.com/threat-signal-report/6668/java4shell (Threat Signal 6668)
- **Tenable:** https://www.tenable.com/cve/CVE-2026-114938/plugins (plugins 382091 and 382045)
- **Qualys, Rapid7 and Snyk:** Qualys QID 389494 (plus 389610 and 389608), a Rapid7 authenticated check in its 17 November 2026 content release, and Snyk entries for RHEL 10 and CentOS 10 packages and the Conan openjdk package
- **Cloudflare:** https://developers.cloudflare.com/waf/change-log/ (no Java4Shell entry, newest item 12 November 2026)
- **No rule or template yet:** nothing from Emerging Threats Open (last build 17 November 2026, 21:59 UTC) or Sigma, and Elastic has a community rule proposal only (issue 7199). A version scanner can't see the CPU or the JVM flags, and a dependency scanner can't see the runtime
- Treat GitHub repositories that claim to be proofs of concept as unreviewed and untrusted

### Platform and product documentation

- **Google Cloud:** https://cloud.google.com/support/bulletins (GCP-2026-082, the interim masking of AVX-512 VBMI through 30 November 2026)
- **Heroku:** https://devcenter.heroku.com/changelog-items/3919 (defaults moved to 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, effective 18 November 2026)
- **Azure Functions:** https://github.com/Azure/azure-functions-java-worker/issues/909 (the worker's default flags keep the vulnerable path off) and https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-java
- **Java launcher and jcmd:** https://docs.oracle.com/en/java/javase/21/docs/specs/man/java.html and https://docs.oracle.com/en/java/javase/21/docs/specs/man/jcmd.html
- **Elasticsearch JVM settings:** https://www.elastic.co/docs/reference/elasticsearch/jvm-settings
- **Jira bundled Java:** https://confluence.atlassian.com/adminjiraserver106/bundled-tomcat-and-java-versions-1573488112.html
- **Confluence bundled Java:** https://confluence.atlassian.com/doc/bundled-tomcat-and-java-versions-1005786018.html
- **No statement found:** AWS Lambda, Elastic Beanstalk, Azure App Service and Azure Functions (Microsoft), and the product vendors Atlassian, Jenkins, Keycloak, JFrog, Elastic, Apache (Tomcat, Kafka, Solr), Cisco, IBM and SAP. Ping Identity and Broadcom could not be checked

### Emergency support contacts

- **Product and platform vendors:** the vendor's security contact (not an incident hotline)
- **CISA:** report@cisa.gov or +1 888-282-0870
- **FBI Internet Crime Complaint Center (IC3):** report online (US)
- **CERT-In (India):** incident@cert-in.org.in or 1800-11-4949
- **NCSC-UK:** its online incident reporting service
- **Your Java vendor's or Linux distributor's security team, your cloud provider's security contact and your incident response retainer**

---

## QUICK REFERENCE CARD

### Print and post this

```
===============================================================
  JAVA4SHELL (CVE-2026-114938): HEAP OVERFLOW IN THE JVM
  Oracle CVSS 3.1: 8.1 | Red Hat: Critical, 9.8 (preliminary)
===============================================================

AFFECTED:
  Java 17.0.6 and later, every 18 to 27 release, and Oracle's
  Java 8 Performance Pack (8u511b33-perf and earlier)
  The .0.2 and .0.3 respins look new but are vulnerable:
  17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3

FIXED IN (17 November 2026):
  17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, 8u513-perf
  Other vendors number builds differently (Corretto
  17.0.21.1.2, Zulu 17.70.201): use your vendor's own list

NOT AFFECTED BY THIS CVE:
  Java 8 (standard), Java 11, 17.0.0 to 17.0.5, ARM64,
  x86-64 without AVX-512 VBMI. Take the November updates
  on Java 8 and 11 anyway: they fix other flaws

---------------------------------------------------------------
YOU ARE EXPOSED WHEN ALL OF THESE ARE TRUE:
---------------------------------------------------------------

  1. An affected build (see above)
  2. x86-64 CPU with AVX-512 VBMI (Intel Xeon Ice Lake,
     Sapphire Rapids, Emerald Rapids, Granite Rapids; AMD
     Zen 4 and later; Intel client Ice Lake, Tiger Lake and
     Rocket Lake)
  3. JVM defaults on: UseBASE64Intrinsics true, UseAVX 3,
     C2 compiler running
  4. The app passes attacker-supplied Base64 to the basic or
     URL-safe decoder (logins, tokens, SAML)

  A WAF or proxy in front does not clear you. Java programs
  that open TLS connections to servers you don't control
  are in scope too (Calif's client-side claim)

---------------------------------------------------------------
PRIORITY ORDER:
---------------------------------------------------------------

  FIRST: internet-facing, VBMI hardware, affected build.
  Identity and single sign-on servers, CI and artifact
  servers, Jira and Confluence lead the list
  NEXT: internal services on VBMI hardware, and Java
  programs that open TLS connections to outside servers
  THEN: ARM64 and non-VBMI x86, in the normal window

---------------------------------------------------------------
IMMEDIATE ACTIONS:
---------------------------------------------------------------

1. CHECK (1 minute), as the JVM's user or root:
   # Running JVMs (in a container: run it inside)
   jcmd -l
   # Live version of one JVM
   jcmd <pid> VM.version
   # Is the path on? Read UseAVX and UseBASE64Intrinsics
   jcmd <pid> VM.flags -all
   # Prints avx512vbmi if this CPU has it
   grep -o -w avx512vbmi /proc/cpuinfo | head -1
   Exposed: UseAVX 3 and UseBASE64Intrinsics true, on a
   VBMI CPU, with C2 running. Not exposed: the flag is
   false, UseAVX is 2 or lower, or TieredStopAtLevel is 1

2. FIX, as root, then RESTART every JVM that used the old
   runtime (a runtime on disk does not fix a live JVM) and
   rebuild container images:
   # Amazon Linux 2
   yum update --advisory ALAS2-2026-4123
   # Amazon Linux 2023: the dnf line in PROTECTION ROADMAP
   # Arch Linux
   pacman -Syu
   # Homebrew (as your normal user), for each formula
   brew update && brew upgrade openjdk@21
   # Docker: rebuild on a fixed base, then redeploy
   FROM amazoncorretto:21
   No fixed build yet at the cut-off: Temurin, Microsoft,
   Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM
   Community, Oracle Linux, Rocky Linux, AlmaLinux. Use
   step 3 until then

3. CAN'T PATCH TODAY? Switch the path off, then restart.
   # Preferred: add to the service's environment, keeping
   # any value already there
   JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
   Java 11 and later only: Java 8 does not know the flag
   and will not start. Alternative: -XX:UseAVX=2 (x86-64
   only). Products with their own launcher need the flag
   in their own settings:
   Keycloak: JAVA_OPTS_APPEND, never JAVA_OPTS
   Elasticsearch: a file in config/jvm.options.d/ (it
   strips JAVA_TOOL_OPTIONS)
   Jira: JVM_SUPPORT_RECOMMENDED_ARGS
   Confluence, Tomcat: CATALINA_OPTS
   Jenkins container: JENKINS_JAVA_OPTS
   Kafka: KAFKA_OPTS
   PingFederate: pingfederate/bin/jvm-memory.options
   Remove the flag once the fixed runtime is confirmed

4. CONFIRM THE LIVE JVM, not the file on disk:
   # Live version of one JVM
   jcmd <pid> VM.version
   # Version inside a container image, not the tag name
   docker exec <container> java -version
   # Flags of the live JVM: look for UseBASE64Intrinsics
   jcmd <pid> VM.flags -all

5. BEHIND A WAF OR PROXY? A layer, not a fix:
   AWS WAF Known Bad Inputs 1.28 has Java4Shell rules in
   Count mode: they log, they do not block, until you
   change the action. Do not assume any WAF or proxy blocks
   the bug. Size limits alone won't stop it: the malformed
   input is short (our reading)

---------------------------------------------------------------
WHAT TO WATCH (no indicators of compromise are published
beyond scanner traffic):
---------------------------------------------------------------

  JVM crash logs (hs_err_pid files) and repeated restarts
  Bursts of IllegalArgumentException from
  java.util.Base64$Decoder on endpoints needing no login
  Java processes starting shells or download tools, and new
  outbound connections from Java processes
  Oversized or binary-looking responses from endpoints that
  echo decoded input (our reading: only sign of a memory read)
  A quiet log proves little: many frameworks swallow the
  exception without logging it

---------------------------------------------------------------
THREAT LEVEL (18 November 2026, 08:00 UTC):
---------------------------------------------------------------

  No exploitation in the wild confirmed. Not in CISA KEV.
  CISA SSVC: Exploitation none, Automatable no, Technical
  impact total. No EPSS score yet
  GreyNoise (07:18 UTC): 3 IPs, 53 requests, 0 intrusions
  Calif claims code execution before login in six products.
  Independent labs reproduced crashes and a memory read,
  not code execution
  VulnCheck has a full exploit for paying customers (since
  23:00 UTC on 17 November). Calif's chains are private
  25 GitHub repositories mention the CVE, none verified: do
  not run them

---------------------------------------------------------------
IF COMPROMISED:
---------------------------------------------------------------

  1. Isolate the server (keep it running for evidence)
  2. Capture the process list, network connections and logs
     BEFORE any restart or patch. Preserve logs. Do NOT
     delete anything. Heap dumps and crash logs hold
     secrets: treat them as sensitive
  3. Rotate the secrets the JVM held (signing keys, stored
     credentials, API keys, database passwords) and
     invalidate the sessions and tokens it issued
  4. Bring in incident response, legal and your insurer
  5. Contact: [Your security team / CISO]

---------------------------------------------------------------
MORE INFORMATION:
---------------------------------------------------------------

  Oracle:   Critical Security Patch Update, November 2026
  OpenJDK:  advisory of 17 November 2026
  Red Hat:  bulletin RHSB-2026-018
  Calif:    the Java4Shell write-up
  Vendors:  the CVE page of your Java vendor or distro (see
            ADDITIONAL RESOURCES)

  Emergency Support: [Your IT Security Contact]
  Phone: [Phone Number]
  Email: [Email Address]

===============================================================
   A fixed runtime on disk with the old JVM still running
                  is not fixed. Patch, then restart.
===============================================================

Document Version: 1.0
Last Updated: 18 November 2026
Data cut-off: 18 November 2026, 08:00 UTC
Classification: TLP:CLEAR, public distribution
```

*Sources: Oracle Critical Security Patch Update, OpenJDK advisory, CVE record, Red Hat bulletin RHSB-2026-018, Calif write-up, vendor and distro advisories, CERT notices. Details are in the sections above.*

---

## FINAL RECOMMENDATIONS

### The bottom line

**If every live JVM runs a fixed build (checked against your own vendor's list) and has been restarted:**

- You're fixed for this CVE
- Keep the detection on: JVM crash logs, restart counts, Java processes starting shells
- Take off any flag you set as a stopgap once the fixed runtime is confirmed
- Ignore a scanner or a write-up that cites 17.0.11 and 21.0.3 as fixes (Upwind lists that as a wrong claim)

**If you run an internet-facing Java service on an affected build, on x86-64 with AVX-512 VBMI:**

- Install the fixed build and restart today. Where no fixed build exists or a restart has to wait, start the JVM with -XX:-UseBASE64Intrinsics and restart. It is a bridge, not a fix
- Identity and single sign-on servers, CI and artifact servers, and Jira and Confluence go first. If one of them stayed unpatched and unflagged after 21:00 UTC on 17 November 2026, rotate its signing keys and stored credentials after patching, and invalidate the sessions and tokens it issued
- Check crash logs and process history as far back as retention allows, and for other affected services since 9 September 2026

**If you run Temurin, Microsoft Build of OpenJDK, Red Hat, BellSoft, Debian, Ubuntu, SUSE, Alpine, GraalVM Community, Oracle Linux, Rocky Linux or AlmaLinux builds:**

- None had shipped a fixed build at the cut-off. Apply the flag now, and update the day your vendor's advisory lands

**If you run Amazon Linux or Corretto, Azul Zulu, SAP SapMachine, Oracle Java SE or Oracle GraalVM, Arch Linux or Homebrew:**

- Fixed builds exist. Install the one your vendor names, restart, and rebuild images on a fixed base. The versions are under ADDITIONAL RESOURCES

**If you run Java 8 or 11, or Java 17.0.0 to 17.0.5:**

- Not affected by this CVE. Take the November updates anyway, because they fix other flaws, and don't add the Base64 flag to a Java 8 JVM

**If you run ARM64 or x86-64 without AVX-512 VBMI:**

- Not exposed on the hardware side. Take the fixed build in the normal window, because workloads move between machine types

**If you run a retired Java line (18 to 20, 22 to 24 or 26):**

- No fix will come. Move to 21.0.13.1, 25.0.5.1 or 27.0.1.1, and use the flag until you have

**If you run Jira, Confluence, Elasticsearch, Jenkins, Keycloak, PingFederate, Tomcat or Kafka:**

- The Java inside the product is separate from the system Java. Set the flag through the product's own settings today (Elasticsearch and Keycloak have their own traps), ask the vendor in writing, and update when its fix ships

**If you run on Google, Heroku, Azure Functions or AWS:**

- Google masked VBMI on App Engine standard and Cloud Run second generation only through 30 November 2026, and not on the other Google platforms. Heroku moved its defaults to fixed builds on 18 November. Azure Functions' default flags keep the vulnerable path off. AWS Lambda and Elastic Beanstalk have no statement

**If you run Docker images or Kubernetes:**

- Rebuild on a fixed base (FROM amazoncorretto:21) and redeploy. Check java -version inside the image, not the tag name, and treat a node pool that contains any VBMI node as exposed (our reading)

**If you don't know what Java you run:**

- Find out in the next two hours. Start with the inventory commands under AM I AFFECTED? SELF-ASSESSMENT

### Takeaway for leadership

CVE-2026-114938 (Java4Shell) is simple to scope once you know where to look, and easy to get wrong if you judge by a version string or by a processor you haven't checked. Its severity label depends on who you ask: Oracle scores it 8.1, Red Hat 9.8, Amazon Linux 8.8 and Calif 9.2, and the gap comes from different assumptions about attack complexity and about who the attacker is. Exposure turns on four things at once: an affected build, a processor with AVX-512 VBMI, the JVM defaults left on, and an application that decodes Base64 from outsiders. Most teams haven't mapped which of their runtimes meet all four. Version numbers mislead: the .0.3 respins look newer and are the last vulnerable builds, vendors number their builds differently, and the copy of Java inside a product is separate from the system Java. Whether the bug gives reliable code execution is disputed. Calif says it achieved it before login in six products, while independent labs have reproduced crashes and a memory read but not code execution, and no exploitation has been confirmed. Don't wait for that argument. The timing is not in dispute: the problem and the fix approach were public from 9 September 2026, about ten weeks before the release, the coordinated release came at 21:00 UTC on 17 November (Calif's stated time), and a commercial exploit followed two hours later. A fix needs a restart, so a JVM stays exposed until it restarts.

Use the incident to fix four things:

1. Know every Java runtime you run, including bundled copies and container images, and which processor each one runs on
2. Know which products carry their own Java, and where each one takes JVM flags
3. Retire Java lines that get no fixes, and golden images that carry an affected runtime
4. Treat the restart as part of patching, and check the live JVM with jcmd, not the file on disk

### Remember

- The problem and the fix approach were public from 9 September 2026, about ten weeks before the release
- The .0.2 and .0.3 builds look newer and are the last vulnerable ones. The fix is the .1 build
- A fix only counts once the live JVM is the fixed one
- -XX:-UseBASE64Intrinsics is the preferred stopgap, and where it goes decides whether it works: Elasticsearch strips JAVA_TOOL_OPTIONS, and Keycloak's JAVA_OPTS replaces its defaults
- Our reading: ARM64 and older Intel are clear of this bug by accident, and the newest Java on the newest x86 hardware is the exposed combination
- Java 8 and 11 are not affected by this CVE, but they still need the November updates
- Independent labs have reproduced crashes and a memory read, not Calif's code execution
- Do not assume a WAF or proxy blocks it: AWS's Java4Shell rules only count until you change the action, and IONIX says its WAF rules only partially mitigate
- Clean logs prove little: no indicators of compromise have been published beyond scanner traffic
- Don't run the public repositories named after the CVE
- Patch first, argue about 8.1 versus 9.8 later

**Patch or flag Java today. Restart every JVM today.**

---

**Document Version:** 1.0
**Last Updated:** 18 November 2026
**Data cut-off:** 18 November 2026, 08:00 UTC
**Classification:** TLP:CLEAR, public distribution
**Prepared by:** 0xDTC (TheSecureLancer)

Facts in this document come from Oracle and the OpenJDK project, the CVE record, JDK vendor and distro advisories, CERT notices, research write-ups, tool documentation, and press coverage listed above. Where those sources disagree, the document says so.
