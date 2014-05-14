CFLAGS=-Wall -fPIC -fpermissive -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

CXXFLAGS=-Wall -fPIC -fpermissive -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

all: rec

GENERATED=../build/generated/c/curves.cpp \
	  ../build/generated/include/de_quisquis_ec_impl_pp_CryptoppNative.h

OBJS=curves.o generate.o encrypt.o decrypt.o sign.o verify.o helpers.o

rec: $(GENERATED)
	rm -rf ../build/c
	mkdir -p ../build/c
	cp -r * $(GENERATED) ../build/c
	make -C ../build/c lib

../build/generated/c/curves.cpp: ../src/de/quisquis/ec/Curve.java gencurve.sh
	./gencurve.sh

../build/generated/include/de_quisquis_ec_impl_pp_CryptoppNative.h: ../src/de/quisquis/ec/impl/pp/CryptoppNative.java
	cd ..; ant jni

lib: libcryptoppjava.so

libcryptoppjava.so: $(OBJS)
	$(CXX) -shared -o $@ -lcryptopp $(OBJS)

clean:
	rm -rf ../build/c ../build/generated/c
