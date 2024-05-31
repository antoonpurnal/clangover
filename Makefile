CURRENT_DIR := $(shell pwd)

attack: ref
	clang -O3 -o clangover attack.c kyber/ref/randombytes.c -Lkyber/ref/lib \
	-l:libpqcrystals_kyber512_ref.so -l:libpqcrystals_fips202_ref.so \
	-Ikyber/ref/ -Wl,-rpath,$(CURRENT_DIR)/kyber/ref/lib -DKYBER_K=2 -Wall

ref: 
	sed -i 's/-O3/-Os/g' kyber/ref/Makefile && \
	CC=clang make -C kyber/ref shared

run: 
	./clangover

clean:
	-$(RM) -f clangover
	@make -C kyber/ref clean
