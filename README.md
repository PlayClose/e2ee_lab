# e2ee_lab

<!-- GETTING STARTED -->
## Getting Started

It is one take project now

### Build 
	
```sh
sudo apt install python3-pip
```
```sh
pip install conan --break-system-packages
```
```sh
conan install . --output-folder=build --build=missing
```
```sh
cd ./build
```
```sh
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
```
```sh
cmake --build . -j 13
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage
```sh
cd ./build/bin
./server
./client 127.0.0.1
./client 127.0.0.1
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>
