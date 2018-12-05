### run

```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/delta_generator
export PATH=$PATH:$PWD/delta_generator:$PWD/chromite/bin
#delta update .eg:
python update_server.py  --image=/home/baozhu/u750/chromiumos/src/build/images/beaglebone/latest/chromiumos_image.bin --src_image=/home/baozhu/u750/chromiumos/src/build/images/beaglebone/R72-11238.0.2018_12_03_1501-a1/chromiumos_image.bin --board=beaglebone --host_log 
```
