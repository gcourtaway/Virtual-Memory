#!/bin/sh

name=$(echo $1 | awk '{ print $1 }')
dir=$(find ../ -name $name)

sample_dir='../tests/userprog/sample.txt'
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -s -k -p $dir -a $name -- -f -q  
pintos -s -k -p $sample_dir -a sample.txt -- -q 

pintos -q run "$1"

rm filesys.dsk
