#! /bin/sh
autoreconf --install --force
sh configure
make check
