<p align="center">
 <a href="https://imaal.byu.edu">
  <img src="https://avatars0.githubusercontent.com/u/25964963?s=400&u=c9cae591f5520ec4df753cca0d3f30bab163f00b&v=4" width="25%">
 </a>
 <br>
 <h3>Source code for PAM 2021 Paper - <i> A Peek Into the DNS Cookie Jar: An Analysis of DNS Cookie Use </i></h3>
</p>

---


### Info
* Nearly all code is designed for python 3.6+ (code written for python2 is marked in header comment)
* Most scripts use json lines (jsonl) for their input/output
  * A heavily used script for working with this format is `shared/jsonl-parser`. This script was often used to gather numbers presented in the paper via its filtering methods
* `shared` is a private package used in our lab and is imported throughout the code. All necessary files are included in the `shared` directory.
* We've replaced our authoritative server SLD with `example.com` in all instances where it is used
* This code is provided as-is and for reference. It may take some effort to run it (replacing imports, configuring servers, etc.)
  * If any aspects of the code/setup are unclear feel free to reach out via contact information in the paper.
