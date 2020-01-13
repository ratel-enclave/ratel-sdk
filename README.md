Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux\* Intel(R) SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software (PSW). The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the out-of-tree driver for the Linux\* Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. 

The repository provides a reference implementation of a Launch Enclave for 'Flexible Launch Control' under [psw/ae/ref_le](psw/ae/ref_le). The reference LE implemenation can be used as a basis for enforcing different launch control policy by the platform developer or owner. To build and try it by yourself, please refer to the [ref_le.md](psw/ae/ref_le/ref_le.md) for details.

License
-------
See [License.txt](License.txt) for details.

Contributing
-------
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](https://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf)

Build and Install the Intel(R) SGX Driver
-----------------------------------------
Follow the instructions in the [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project to build and install the Intel(R) SGX driver.

Build the Intel(R) SGX SDK Package
-------------------------------------------------------
### Prerequisites:
- Ensure that you have one of the following required operating systems:  
  * Ubuntu\* 16.04.3 LTS Desktop 64bits
  * Ubuntu\* 16.04.3 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.4 64bits
  * CentOS 7.4.1708 64bits
  * SUSE Linux Enterprise Server 12 64bits

- Use the following command(s) to install the required tools to build the Intel(R) SGX SDK:  
  * On Ubuntu 16.04:
  ```
    $ sudo apt-get install build-essential ocaml automake autoconf libtool wget python
  ```
  * On Red Hat Enterprise Linux 7.4 and CentOS 7.4:
  ```
    $ sudo yum groupinstall 'Development Tools'
    $ sudo yum install ocaml wget python
  ```
  * On SUSE Linux Enterprise Server 12:
  ```
    $ sudo zypper install --type pattern devel_basis
    $ sudo zypper install ocaml ocaml-ocamlbuild automake autoconf libtool wget python
  ```
- Use the script ``download_prebuilt.sh`` inside source code package to download prebuilt binaries to prebuilt folder  
  You may need set an https proxy for the `wget` tool used by the script (such as ``export https_proxy=http://test-proxy:test-port``)  
```
  $ ./download_prebuilt.sh
```

### Build the Intel(R) SGX SDK
The following steps describe how to build the Intel(R) SGX SDK. You can build the project according to your requirements.  
- To build both Intel(R) SGX SDK with default configuration, enter the following command:  
```
  $ make  
```  
  You can find the tools and libraries generated in the `build/linux` directory.  
  **Note**: You can also go to the `sdk` folder and use the `make` command to build the Intel(R) SGX SDK component only. However, building the PSW component is dependent on the result of building the Intel(R) SGX SDK.  

- This repository supports to build the Intel(R) SGX SDK based on either precompiled optimized IPP/string/math libraries or open sourced version of SGXSSL/string/math libraries. 
  The default build uses precompiled optimized libraries, which are downloaded by the script ``./download_prebuilt.sh``.
  You can also use the open sourced version implementation instead by entering the following command:
```
  $ make USE_OPT_LIBS=0
```
  **Note**: Building the Intel(R) SGX PSW with open sourced SGXSSL/string/math libraries is not supported. The above command builds Intel(R) SGX SDK only and the build of PSW part will be skipped.

- To build Intel(R) SGX SDK with debug information, enter the following command:  
```
  $ make DEBUG=1
```
- To clean the files generated by previous `make` command, enter the following command:  
```
  $ make clean
```

- The build above uses prebuilt Intel(R) Architecture Enclaves(LE/PvE/QE/PCE/PSE-OP/PSE-PR) and applet(PSDA) - the files ``psw/ae/data/prebuilt/libsgx_*.signed.so`` and ``psw/ae/data/prebuilt/PSDA.dalp``, which have been signed by Intel in advance.
  To build those enclaves by yourself (without a signature), first you need to build both Intel(R) SGX SDK with the default configuration. After that, you can build each Architecture Enclave by using the `make` command from the corresponding folder:
```
  $ cd psw/ae/le
  $ make
``` 

### Build the Intel(R) SGX SDK Installer
To build the Intel(R) SGX SDK installer, enter the following command:
```
$ make sdk_install_pkg
```
You can find the generated Intel(R) SGX SDK installer ``sgx_linux_x64_sdk_${version}.bin`` located under `linux/installer/bin/`, where `${version}` refers to the version number.

**Note**: The above command builds the Intel(R) SGX SDK with default configuration firstly and then generates the target SDK Installer. To build the Intel(R) SGX SDK Installer with debug information kept in the tools and libraries, enter the following command:
```
$ make sdk_install_pkg DEBUG=1
```


Install the Intel(R) SGX SDK
------------------------
### Prerequisites
- Ensure that you have one of the following operating systems:  
  * Ubuntu\* 16.04.3 LTS Desktop 64bits
  * Ubuntu\* 16.04.3 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.4 64bits
  * CentOS 7.4.1708 64bits
  * SUSE Linux Enterprise Server 12 64bits
- Use the following command to install the required tool to use Intel(R) SGX SDK:
  * On Ubuntu 16.04:
  ```  
    $ sudo apt-get install build-essential python
  ```
  * On Red Hat Enterprise Linux 7.4 and CentOS 7.4:
  ```
     $ sudo yum groupinstall 'Development Tools'
     $ sudo yum install python 
  ```
  * On SUSE Linux Enterprise Server 12:
  ```
     $ sudo zypper install --type pattern devel_basis
     $ sudo zypper install python 
  ```

### Install the Intel(R) SGX SDK
To install the Intel(R) SGX SDK, invoke the installer, as follows:
```
$ cd linux/installer/bin
$ ./sgx_linux_x64_sdk_${version}.bin 
```
NOTE: You need to set up the needed environment variables before compiling your code. To do so, run:  
```  
  $ source ${sgx-sdk-install-path}/environment  
```  

### Test the Intel(R) SGX SDK Package with the Code Samples
- Compile and run each code sample in Simulation mode to make sure the package works well:    
```
  $ cd SampleCode/LocalAttestation
  $ make SGX_MODE=SIM
  $ ./app
```
   Use similar commands for other sample codes.

### Compile and Run the Code Samples in the Hardware Mode
If you use an Intel SGX hardware enabled machine, you can run the code samples in Hardware mode.
Ensure that you install Intel(R) SGX driver and Intel(R) SGX PSW installer on the machine.  
See the earlier topic, *Build and Install the Intel(R) SGX Driver*, for information on how to install the Intel(R) SGX driver.  
See the later topic, *Install Intel(R) SGX PSW*, for information on how to install the PSW package.
- Compile and run each code sample in Hardware mode, Debug build, as follows:  
```
  $ cd SampleCode/LocalAttestation
  $ make
  $ ./app
```
   Use similar commands for other code samples.


### Start or Stop aesmd Service
The Intel(R) SGX PSW installer installs an aesmd service in your machine, which is running in a special linux account `aesmd`.  
To stop the service: `$ sudo service aesmd stop`  
To start the service: `$ sudo service aesmd start`  
To restart the service: `$ sudo service aesmd restart`

### Configure the Proxy for aesmd Service
The aesmd service uses the HTTP protocol to initialize some services.  
If a proxy is required for the HTTP protocol, you may need to manually set up the proxy for the aesmd service.  
You should manually edit the file `/etc/aesmd.conf` (refer to the comments in the file) to set the proxy for the aesmd service.  
After you configure the proxy, you need to restart the service to enable the proxy.
