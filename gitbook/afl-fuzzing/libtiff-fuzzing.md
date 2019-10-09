# Fuzzing libtiff

```
wget http://download.osgeo.org/libtiff/tiff-4.0.9.tar.gz
tar xzvf tiff-4.0.9.tar.gz
cd tiff-4.0.9

```
export CC=afl-clang-fast
export CXX=afl-clang-fast++
```

```
./configure --prefix=/opt/libtiff
make
sudo make install
```

```
afl-fuzz -i /tmp/tiff/input/ -o /tmp/tiff/output/ -- /opt/libtiff/bin/tiff2ps @@
```