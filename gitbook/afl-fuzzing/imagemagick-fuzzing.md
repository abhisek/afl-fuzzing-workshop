# Fuzzing ImageMagick

Obtain source code and extract

```
wget -O imagemagick.tar.gz \
  https://github.com/ImageMagick/ImageMagick/archive/7.0.8-68.tar.gz

tar xzvf imagemagick.tar.gz
cd ImageMagick-7.0.8-68
```

Set compiler to `AFL`

```
export CC=afl-clang-fast
export CXX=afl-clang-fast++
```

Build and compile

```
./configure --prefix=/opt/ImageMagick-AFL
make
sudo make install
```

At this point, ImageMagick libraries and binaries are installed in `/opt/ImageMagick-AFL`.

Create input and output directory for fuzzer

```
mkdir -p /tmp/magick/input /tmp/magick/output
```

Seed the input directory to random file samples



