kfetch-toolkit
==============

The kfetch-toolkit project is designed to perform advanced logging of memory references performed by operating systems’ kernels and examine the resulting logs in search of specific patterns indicating presence of software bugs, often of security nature. Information about memory references is obtained by running a guest operating system of choice using the latest version of the Bochs IA-32 Emulator Project  with a custom instrumentation component.

Find the official documentation in kfetch-toolkit.pdf.

More information:
http://vexillium.org/dl.php?syscan_slides.pdf - SyScan 2013 slides, "Bochspwn: Exploiting Kernel Race COnditions Found via Memory Access Patterns"
http://vexillium.org/dl.php?bochspwn.pdf - SyScan 2013 whitepaper, "Identifying and Exploiting Windows Kernel Race Conditions via Memory Access Patterns"
http://j00ru.vexillium.org/?p=1880 and http://gynvael.coldwind.pl/?id=509 - follow up blog posts, "Kernel double-fetch race condition exploitation on x86 - further thoughts"
