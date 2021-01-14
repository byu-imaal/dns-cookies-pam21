**Source code for PAM 2021 Paper - A Peek Into the DNS Cookie Jar: An Analysis of DNS Cookie Use**

## Info
* Nearly all code is designed for python 3.6+ (code written for python2 is marked in header comment)
* Most scripts use json lines (jsonl) for their input/output
  * A heavily used script for working with this format is `shared/jsonl-parser`. This script was often used to gather numbers presented in the paper via its filtering methods
* `shared` is a private package used in our lab and is imported throughout the code. All necessary files are included in the `shared` directory.
* We've replaced our authoritative server SLD with `example.com` in all instances where it is used
* This code is provided as-is and for reference. It may take some effort to run it (replacing imports, configuring servers, etc.)
  * If any aspects of the code/setup are unclear feel free to reach out via contact information in the paper.
