# gochia

[chia-blockchain](https://github.com/Chia-Network/chia-blockchain) some function implement in golang

## Package

- bls-signatures implement [blspy](https://github.com/Chia-Network/bls-signatures)

## Usage?

Now we can use it to generate plot `memo` and `id`, see [memo_test.go](./plotting/memo_test.go).

When got `memo` and `id`, we direct call 
[ProofOfSpace](https://github.com/Chia-Network/chiapos) `-m $(memo) -i $(id)` to plot

## License

MIT