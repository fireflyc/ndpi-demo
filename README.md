nDPI演示代码
编译方法
保证机器上安装了cmake、libpcap-dev、libconfig-dev
```
mkdir build && cd build
cmake ..
make
```
最终生成ndpi-demo，执行它需要两个参数分别是配置文件和日志文件，对应代码中ndpi-demo.conf和logging.conf

