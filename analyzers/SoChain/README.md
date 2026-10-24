### SoChain

[SoChain](https://sochain.com/) is a block explorer and API for Bitcoin, Litecoin, Dogecoin and Zcash.

The analyzer takes a `crypto_address` or `btc_address` observable and reports:

- the network: `btc_address` is looked up on Bitcoin; for `crypto_address` it is the first of Bitcoin, Litecoin, Dogecoin and Zcash on which SoChain says the address is valid;
- the balance, total received and sent, the number of transactions, and the first and last activity;
- whether the address was targeted by address poisoning: look-alike addresses that sent it dust, imitating an address it paid or was paid by;
- its recent counterparties (who it paid and was paid by), with amounts and transactions.

Look-alike addresses and counterparties are returned as artifacts, of the observable's data type, tagged `sochain:address-poisoning` or `sochain:counterparty`.

#### Requirements

None. Without an API key, lookups work up to 2,500 a day per IP, shared by everything on the Cortex host. For more, set `key` to an API key from https://sochain.com/dashboard; it is sent as the `API-KEY` header.

#### Tests

```
cd analyzers/SoChain
python3 -m unittest test_sochain
```

The tests mock HTTP and make no network calls.
