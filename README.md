# mem-infector

## How to build the examples:

```shell
  ./build.sh
```

## How to use:
```
  运行本程序需满足 1.内核为linux标准内核（标准内核指来源linux内核官网或者一些正规渠道，有些非正规渠道提供的内核因为开发者的修改导致丧失一些基本特性），2.CPU架构为X86_64
  ./build/install/demo/virus 
  usage: ./build/install/demo/virus [options] ...
  options:
      -p        , --pid                    set target pid
                                          parameter range is [1 , 1000000]
      -l        , --link                   link so
                                          option depends [ --pid ]
      -ga       , --getfunaddr             get target process function addr
                                          option depends [ --pid ]
      -sl       , --setloglevel            set log level
                                          parameter range is [ info error debug warning all ]
      -o        , --outputfile             set output log file
      -sa       , --setaddr                set target mem addr
                                          option depends [ --pid ]
      -w        , --write                  write str to target mem
                                          option depends [ --pid --setaddr ]
      -r        , --read                   read str from target mem
                                          option depends [ --pid --setaddr ]
      -ho       , --hook                   hook syscall
                                          option depends [ --pid --link ]
      -v        , --version                get version
      -h        , --help                   print help message
```
