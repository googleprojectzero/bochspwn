# Bochspwn

Bochspwn is a system-wide instrumentation project designed to log memory accesses performed by operating system kernels and examine them in search of patterns indicating the presence of certain bugs, such as "double fetches". Information about memory references is obtained by running the guest operating systems within the [Bochs IA-32 emulator](http://bochs.sourceforge.net/) with the custom instrumentation component compiled in. It was written in 2013, and was used to discover over 50 race conditions in the Windows kernel, fixed across numerous security bulletins ([MS13-016](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-016), [MS13-017](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-017), [MS13-031](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-031), [MS13-036](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-036)). For further information, see [Read more](#read-more).

## Support status

The toolset is not actively maintained, and its source code is released "as is", mostly for reference purposes. It was originally released as *kfetch-toolkit* in 2013 after the Black Hat USA talk, together with a comprehensive documentation at [DOCUMENTATION.old.md](DOCUMENTATION.old.md) (now partially obsolete). In 2017, we revised the source code of the project and implemented several new features:

1. Information about the address space layout of kernel drivers is stored in a separate file (`modules.bin` by default), and each driver is referenced by its index in the main log file. This was done to save disk space, by preventing the reduntant information (image names and base addresses) from being needlessly saved for every stack trace item in the log.
2. Information about the presence of an active exception handler in each stack frame was added to the access log protocol buffer, allowing us to detect a number of local Windows DoS vulnerabilities (see examples [1](https://j00ru.vexillium.org/2017/02/windows-kernel-local-denial-of-service-1/), [2](https://j00ru.vexillium.org/2017/02/windows-kernel-local-denial-of-service-2/), [3](https://j00ru.vexillium.org/2017/03/windows-kernel-local-denial-of-service-3/), [4](https://j00ru.vexillium.org/2017/04/windows-kernel-local-denial-of-service-4/)).
3. Information about the value of [`PreviousMode`](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode) at the time of the memory access in Windows was added to the protocol buffer.
4. The "online" double-fetch detection mode was removed from the code, as it was deemed too slow to be practically useful.
5. Some symbolization-related and other minor bugs were fixed in the code.

The instrumentation was also ported to Bochs version 2.6.9, the latest one at the time of this writing.

## Building and usage

For general instructions, see [DOCUMENTATION.old.md](DOCUMENTATION.old.md).

You may wish to use more recent versions of the referenced software (e.g. Bochs 2.6.9, libprotobuf 3.4.1 etc.), and update the Bochspwn configuration file to account for the 2017 changes. When in doubt, please refer to the source code or [contact us](mailto:mjurczyk@google.com) with any questions.

## Example report

```
------------------------------ found double-read of address 0x00000000001ef766
Read no. 1:
[pid/tid/ct: 000000fc/00000100/01d27c3a91e567e6] {        smss.exe} 0000001e, 00000042: READ of 1ef764 (5 * 4 bytes), pc = 82a75263 [ rep movsd dword ptr es:[edi], dword ptr ds:[esi] ]
[previous mode: 1]
#0  0x82a75263 ((0026a263) ntoskrnl!SeCaptureSecurityDescriptor+00000067) <===== SEH enabled (#0)
#1  0x82a36a23 ((0022ba23) ntoskrnl!ObpCaptureObjectCreateInformation+000000c2) <===== SEH enabled (#0)
#2  0x82a45de2 ((0023ade2) ntoskrnl!ObOpenObjectByName+0000009b)
#3  0x82a3c7db ((002317db) ntoskrnl!IopCreateFile+00000673) <===== SEH disabled
#4  0x82a60402 ((00255402) ntoskrnl!NtCreateFile+00000034)
#5  0x82848db6 ((0003ddb6) ntoskrnl!KiSystemServicePostCall+00000000)

Read no. 2:
[pid/tid/ct: 000000fc/00000100/01d27c3a91e567e6] {        smss.exe} 0000001e, 00000042: READ of 1ef766 (1 * 2 bytes), pc = 82a752ad [           movzx edx, word ptr ds:[eax+2] ]
[previous mode: 1]
#0  0x82a752ad ((0026a2ad) ntoskrnl!SeCaptureSecurityDescriptor+000000b1) <===== SEH enabled (#1)
#1  0x82a36a23 ((0022ba23) ntoskrnl!ObpCaptureObjectCreateInformation+000000c2) <===== SEH enabled (#0)
#2  0x82a45de2 ((0023ade2) ntoskrnl!ObOpenObjectByName+0000009b)
#3  0x82a3c7db ((002317db) ntoskrnl!IopCreateFile+00000673) <===== SEH disabled
#4  0x82a60402 ((00255402) ntoskrnl!NtCreateFile+00000034)
#5  0x82848db6 ((0003ddb6) ntoskrnl!KiSystemServicePostCall+00000000)
```

## Read more

* Whitepaper - [Identifying and Exploiting Windows Kernel Race Conditions via Memory Access Patterns](https://j00ru.vexillium.org/papers/2013/bochspwn.pdf)
* SyScan 2013 slides - [Bochspwn: Exploiting Kernel Race COnditions Found via Memory Access Patterns](https://j00ru.vexillium.org/slides/2013/syscan.pdf)
* Black Hat USA 2013 slides - [Bochspwn: Identifying 0-days via System-wide Memory Access Pattern Analysis](https://j00ru.vexillium.org/slides/2013/bhusa.pdf)
* Black Hat USA 2013  video - [Bochspwn: Identifying 0-days via System-wide Memory Access Pattern Analysis on YouTube](https://www.youtube.com/watch?v=ypV0kpi4cd8)
* Blog post - [Kernel double-fetch race condition exploitation on x86 - further thoughts](https://j00ru.vexillium.org/2013/06/kernel-double-fetch-race-condition-exploitation-on-x86-further-thoughts/)

## Bochspwn Reloaded

In 2017, we implemented a new type of full-system instrumentation on top of the Bochs emulator, named *Bochspwn Reloaded*. The instrumentation performs taint tracking of the guest kernel address space, and detects the disclosure of uninitialized kernel stack/heap memory to user-mode. It helped us identify over [70](https://bugs.chromium.org/p/project-zero/issues/list?can=1&q=finder:mjurczyk%20product:kernel%20opened%3E2017-02-23%20opened%3C2018-1-23%20%22uninitialized%20%22memory%20disclosure%22&colspec=ID%20Status%20Restrict%20Reported%20Vendor%20Product%20Finder%20Summary&cells=ids) bugs in the Windows kernel, and more than [10](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/?qt=author&q=mjurczyk@google.com) lesser bugs in Linux in 2017 and early 2018.

The tool was discussed at the [REcon Montreal](https://j00ru.vexillium.org/talks/recon-bochspwn-reloaded-detecting-kernel-memory-disclosure/), [Black Hat USA](https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/), and [INFILTRATE](https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions-further-advancements-in-detecting-kernel-infoleaks/) conferences, as well as in the [  
Detecting Kernel Memory Disclosure with x86 Emulation and Taint Tracking](http://j00ru.vexillium.org/papers/2018/bochspwn_reloaded.pdf) whitepaper. It is also an open-source project, and its source code can be found in the [bochspwn-reloaded](https://github.com/google/bochspwn-reloaded) repository.

## Disclaimer

This is not an official Google product.
