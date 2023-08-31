# KextFuzz

A prototype for the paper [KextFuzz: Fuzzing macOS Kernel EXTensions on Apple Silicon via Exploiting Mitigations [USENIX Security 2023]](https://www.usenix.org/conference/usenixsecurity23/presentation/yin). The code was tested on Apple Silicon macOS 11.5.2.
Thanks for your attention.

## Prerequirement
- Apple Silicon Devices / Virtual Machine with macOS 11
- capstone & keystone

## Kext Instrumentation & Entitlement Patching

The `./rewrite` directory contains the code to do kext instrumentation and entitlement patch.


**Step 1. Get a patched kext.**

Note: edit `./rewrite/config.json` to specify the patch target and strategy.
Instrumentation and Entitlement patching are enabled by default.
```
$ pip install -r requirements.txt
$ cd rewrite
$ python bin_rewrite.py config.json
```
The patched kext will be saved in the `./rewrite/output` directory by default.

**Step 2. Build helper.kext.**

Build the `./rewrite/helper` in XCode to get helper.kext

Note: The helper kext should implement 1) the fake entitlement checker and 2) the profiling function which will be instrumented into the kext. 
The helper.kext in the repository is an example of the helper kext. Please customize your own profiling functions with reference to `./rewrite/helper/helper.cpp`.

**Step 3. Build macOS kernel collection. [reference](https://kernelshaman.blogspot.com/2021/02/building-xnu-for-macos-112-intel-apple.html)**

```
$ kmutil inspect -V release --no-header | grep -v "SEPHiber" | awk '{print " -b "$1; }' > kext_list
$ echo "kextfuzz.example.helper" >> kext_list

# build kernel collection with patched kext and helper kext
$ mkdir Extensions
$ sudo cp -r ./output/* ./Extensions/
$ kmutil create -a arm64e -z -V release -n boot -B /path/to/your.kc -k /System/Library/kernels -r ./Extensions -r /System/Library/DriverExtensions -x $(cat kext_list)"
```


**Step 4. Install the patched kernel collection.**

1. Boot into recovery mode & open terminal.
2. Enter `csrutil disable` to disable System Integrity Protection.
3. Enter `bputil -a` to disable boot args restriction.
4. Reboot to apply above settings.
5. Boot into recovery mode & open terminal.
3. Install kernel collection: `kmutil configure-boot -v /Volumes/your-volume -c /path/to/your.kc`.

## Trouble Shooting

1. View loaded kexts: `kextstat`
2. Load a kext: `kextload /path/to/kext`
3. View Mach-O binary symbols: `nm /path/to/bin`
4. View kernel log: `log stream --predicate "sender=='xxx'"`

## Fuzz for fun

Play the video with sound :)

https://user-images.githubusercontent.com/41458124/228831530-4ef2c75a-4167-48af-8fa2-a100f969d6ba.mp4
