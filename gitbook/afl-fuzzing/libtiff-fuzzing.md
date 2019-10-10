# Fuzzing libtiff

Install required dependencies

```
sudo apt-get install zlib1g-dev
```

Start by downloading and extracting the sources

```
wget http://download.osgeo.org/libtiff/tiff-4.0.9.tar.gz
tar xzvf tiff-4.0.9.tar.gz
cd tiff-4.0.9
```

Set appropriate compiler environment variables

```
export CC=afl-clang-fast
export CXX=afl-clang-fast++
```

Build libtiff with AFL compiler wrapper

```
./configure --prefix=/opt/libtiff
make
sudo make install
```

Create input, output directories and seed input with sample TIFF files. Test the fuzzing process using the command line below

```
afl-fuzz -i /tmp/tiff/input/ -o /tmp/tiff/output/ -- /opt/libtiff/bin/tiff2ps @@
```