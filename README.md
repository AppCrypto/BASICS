# test offchain cost

## test bn128 MA-ABE (python)
	cd ma_abe/bn128 && python3 ma_abe2.py

## test bn128 MA-ABE (golang)
	cd ma_abe/go-bn128 && go run main.go

## test ss512 MA-ABE (python)
	cd ma_abe/ss512 && python3 ma_abe.py 10

# test onchain cost

## open a command line to init ganache
	ganache-cli -l 90071992547 -p 7550

## open another commond line to connect ganache
	python3 main.py