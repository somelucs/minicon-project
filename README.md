# minicon-project

## Overview

The minicon-project repository is a minimalistic containerization framework designed for educational and experimental purposes. It aims to provide a lightweight and straightforward approach to understanding containerization concepts without the overhead of complex systems like Docker or Kubernetes.

## Repository Structure

The project consists of the following key components:

`monitor.bpf.c`: A C program utilizing eBPF (Extended Berkeley Packet Filter) to monitor system calls related to container processes. This file is essential for tracking and managing container activities at the kernel level.

`mycontainer.c`: The core implementation of the container engine. Written in C, this program handles the creation, execution, and management of containerized processes, providing a hands-on understanding of container internals.

`setup.sh`: A shell script that automates the setup process. It compiles the necessary C programs and sets up the environment, ensuring that users can quickly get the project up and running.


## Getting Started

### Prerequisites

Ensure that you have the following installed on your system:

A Linux-based operating system (e.g., Ubuntu, Fedora)

GCC (GNU Compiler Collection) for compiling C programs

Clang and LLVM for eBPF support

BCC (BPF Compiler Collection) for eBPF tools

Root privileges for setting up and monitoring containers


### Installation

Clone the repository to your local machine:

`git clone https://github.com/somelucs/minicon-project.git`
`cd minicon-project`

Run the setup script to compile the necessary programs:

`chmod +x setup.sh`
`./setup.sh`

This script will compile monitor.bpf.c and mycontainer.c, preparing them for execution.

### Usage

To create and run a container:

`sudo ./mycontainer`

To monitor system calls related to the container:

`sudo ./monitor.bpf`

Ensure that both programs are running simultaneously to effectively manage and monitor the container.

## Contributing

Contributions to the minicon-project are welcome. To contribute:

1. Fork the repository.


2. Create a new branch (git checkout -b feature-branch).


3. Make your changes.


4. Commit your changes (git commit -am 'Add new feature').


5. Push to the branch (git push origin feature-branch).


6. Create a new Pull Request.



Please ensure that your code adheres to the existing coding style and includes appropriate tests.
