# mem-infector

## How to build the examples:

```shell
  git submodule init
  git submodule update
  ./build.sh
```

## How to use:
```
  运行本程序需满足 1.内核为linux标准内核（标准内核指来源linux内核官网或者一些正规渠道，有些非正规渠道提供的内核因为开发者的修改导致丧失一些基本特性），2.CPU架构为X86_64
  usage: ./src/virus/virus --pid=int [options] ... 
options:
  -p, --pid      set target pid (int)
  -l, --libso    set libso name (string [=])
  -?, --help     print this message
```
