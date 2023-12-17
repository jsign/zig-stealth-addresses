# Ethereum stealth addresses (ERC-5564) library
This repository is a Zig implementation of the Ethereum stealth addresses ([ERC-5564](https://eips.ethereum.org/EIPS/eip-5564#specification)).

The implementation has zero dependencies (i.e: only relies on Zig standard library).

**Note: this library hasn't been audited, use it at your own risk.**

## What are stealth addresses?
> **Stealth addresses** are a way of protecting the **privacy of recipients** in cryptocurrency transactions.
They allow a sender to **non-interactively** generate a new address for the recipient, making it look like as if the sender interacted with some random account.

## Where I can find more resources about stealth addresses?
- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564#specification) and [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538).
- [Stealth Addresses tutorial](https://nerolation.github.io/stealth-utils/) by Toni Wahrstätter.
- [An incomplete guide to stealth addresses](https://vitalik.eth.limo/general/2023/01/20/stealth.html) by Vitalik.
- Web-based [Stealth wallet](https://stealth-wallet.xyz/) by Toni Wahrstätter.

## How can I use this library?
You can use this library as a dependency in your Zig project by adding it as a dependency to your `build.zig.zon` file.

See the [library tests](https://github.com/jsign/zig-stealth-addresses/blob/511fa7f14875675a8565ecf156d1125b6ca3dfd8/src/stealth_address.zig#L94-L147) for some examples of how to use the defined APIs.

In the future, this repo might include a CLI tool to generate and interact with stealth addresses.

## License
MIT.
