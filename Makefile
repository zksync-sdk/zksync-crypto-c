build_lib:
	cd zks-crypto-c && cargo build --release

run_example:
	cd example-c && cc main.c -o example -l zks_crypto  -L../target/release && ./example
