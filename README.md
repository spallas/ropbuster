# ropbuster
An Intel PIN tool for dynamic detection of Return Oriented Programming attacks

## Instructions

- Download the latest [Intel PIN](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) distribution
- Clone this repository. Move the RopDetect directory in `<pin-home>/source/tools/`.
- To compile the tool go inside the RopDetect/ directory and run `make obj-ia32/RopDetect.dll TARGET=ia32`. If you are on a 64bit system you can still compile the tool, but the test applications and exploits are targeted at Windows 7 32bit system.
- To execute the tool run from within RopDetect/ : `../../../pin -t obj-ia32/RopDetect.dll -- path/to/app`.
