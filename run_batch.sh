#! /bin/sh
autoreconf --install --force
sh configure
cp -rf config.h.unix config.h
make 1>/dev/null 2 > &1
make check
