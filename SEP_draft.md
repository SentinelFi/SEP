# Tokenized Vault Standard SEP

## Preamble

```
SEP: TBD
Title: Tokenized Vault Standard SEP
Author: OpenZeppelin, Boyan Barakov <@brozorec>, Özgün Özerk <@ozgunozerk>, Sentinel <@SentinelFi>
Track: Standard
Status: Draft
Created: 2025-09-16
Updated: 2025-09-16
Version: 0.1.0
Discussion: https://github.com/orgs/stellar/discussions/1787
```

## Summary

This SEP introduces a standard for tokenized vault contracts on Stellar Soroban. A tokenized vault is a smart contract and DeFi primitive that pools funds by allowing users to deposit underlying assets (such as XLM or USDC) and mint a corresponding amount of shares (vault tokens) in return, representing their proportional ownership of the total vault pool. The assets locked in a vault can be utilized by the smart contract logic for yield generation, lending and borrowing, staking, insurance, prediction markets, and other use cases. When users withdraw their assets, their corresponding share tokens are burned.

## Dependencies

Soroban Fungible Token Standard (SEP-41): The standard vault depends on an underlying asset that must be SEP-41 compliant. The vault itself must also comply with SEP-41 and further extend it.

Reference: https://github.com/SentinelFi/stellar-protocol/blob/master/ecosystem/sep-0041.md (Soroban Token Interface).

## Motivation

While the ERC-4626 standard has long existed in the EVM ecosystem, there is currently no standard defining tokenized vaults in Stellar Soroban. This standard is proposed to enable consistent integrations between DeFi projects, making it easier for protocols to interoperate and for developers to build composable DeFi applications using vaults.

## Abstract

This proposal defines a standardized interface (trait) for tokenized vaults on Soroban.

The standard ensures that vaults expose a consistent interface for deposits, withdrawals, asset-to-share conversions, and other related functions. By requiring SEP-41 compliance for both underlying assets and vault tokens, it promotes interoperability across the ecosystem.

The vault standard extends the token interface standard for share tokenization. Any additional extensions implemented alongside this standard affect the "shares" token represented by this contract, not the underlying "assets" token, which remains an independent contract.

## Interface

```rust
/// Tokenized Vault Trait
///
/// The `TokenizedVault` trait follows closely the ERC-4626 tokenized vault 
/// standard, enabling fungible tokens to represent shares in an underlying 
/// asset pool.
/// This extension allows users to deposit underlying assets in exchange for
/// vault shares, and later redeem those shares for the underlying assets.
///
/// The vault maintains a conversion rate between shares and assets based on
/// the total supply of shares and total assets held by the vault contract.
///
/// # Compatibility
///
/// This implementation follows the ERC-4626 standard for tokenized vaults,
/// allowing seamless interoperability across ecosystems.
pub trait TokenizedVault: TokenInterface {
    /// Returns the total amount of tokens in circulation.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    fn total_supply(e: &Env) -> i128;

    /// Returns the address of the underlying asset that the vault manages.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    fn query_asset(e: &Env) -> Address;

    /// Returns the total amount of underlying assets held by the vault.
    ///
    /// This represents the vault's balance of the underlying asset, which
    /// determines the conversion rate between shares and assets.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    fn total_assets(e: &Env) -> i128;

    /// Converts an amount of underlying assets to the equivalent amount of
    /// vault shares (rounded down).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `assets` - The amount of underlying assets to convert.
    fn convert_to_shares(e: &Env, assets: i128) -> i128;

    /// Converts an amount of vault shares to the equivalent amount of
    /// underlying assets (rounded down).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `shares` - The amount of vault shares to convert.
    fn convert_to_assets(e: &Env, shares: i128) -> i128;

    /// Returns the maximum amount of underlying assets that can be deposited
    /// for the given receiver address.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `receiver` - The address that would receive the vault shares.
    fn max_deposit(e: &Env, receiver: Address) -> i128;

    /// Simulates and returns the amount of vault shares that would be minted
    /// for a given deposit of underlying assets (rounded down).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `assets` - The amount of underlying assets to simulate depositing.
    fn preview_deposit(e: &Env, assets: i128) -> i128;

    /// Deposits underlying assets into the vault and mints vault shares
    /// to the receiver, returning the amount of vault shares minted.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `assets` - The amount of underlying assets to deposit.
    /// * `receiver` - The address that will receive the minted vault shares.
    /// * `operator` - The address performing the deposit operation.
    ///
    /// # Events
    ///
    /// * topics - `["deposit", operator: Address, receiver: Address]`
    /// * data - `[assets: i128, shares: i128]`
    fn deposit(e: &Env, assets: i128, receiver: Address, operator: Address) -> i128;

    /// Returns the maximum amount of vault shares that can be minted
    /// for the given receiver address.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `receiver` - The address that would receive the vault shares.
    fn max_mint(e: &Env, receiver: Address) -> i128;

    /// Simulates and returns the amount of underlying assets required to mint
    /// a given amount of vault shares (rounded up).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `shares` - The amount of vault shares to simulate minting.
    fn preview_mint(e: &Env, shares: i128) -> i128;

    /// Mints a specific amount of vault shares to the receiver by depositing
    /// the required amount of underlying assets, returning the amount of 
    /// assets deposited.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `shares` - The amount of vault shares to mint.
    /// * `receiver` - The address that will receive the minted vault shares.
    /// * `operator` - The address performing the mint operation.
    ///
    /// # Events
    ///
    /// * topics - `["deposit", operator: Address, receiver: Address]`
    /// * data - `[assets: i128, shares: i128]`
    fn mint(e: &Env, shares: i128, receiver: Address, operator: Address) -> i128;

    /// Returns the maximum amount of underlying assets that can be
    /// withdrawn by the given owner, limited by their vault share balance.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `owner` - The address that owns the vault shares.
    fn max_withdraw(e: &Env, owner: Address) -> i128;

    /// Simulates and returns the amount of vault shares that would be burned
    /// to withdraw a given amount of underlying assets (rounded up).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `assets` - The amount of underlying assets to simulate withdrawing.
    fn preview_withdraw(e: &Env, assets: i128) -> i128;

    /// Withdraws a specific amount of underlying assets from the vault
    /// by burning the required amount of vault shares from the owner,
    /// returning the amount of vault shares burned.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `assets` - The amount of underlying assets to withdraw.
    /// * `receiver` - The address that will receive the underlying assets.
    /// * `owner` - The address that owns the vault shares to be burned.
    /// * `operator` - The address performing the withdrawal operation.
    ///
    /// # Events
    ///
    /// * topics - `["withdraw", operator: Address, receiver: Address, owner:
    ///   Address]`
    /// * data - `[assets: i128, shares: i128]`
    fn withdraw(
        e: &Env,
        assets: i128,
        receiver: Address,
        owner: Address,
        operator: Address,
    ) -> i128;

    /// Returns the maximum amount of vault shares that can be redeemed
    /// by the given owner (equal to their vault share balance).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `owner` - The address that owns the vault shares.
    fn max_redeem(e: &Env, owner: Address) -> i128;

    /// Simulates and returns the amount of underlying assets that would be
    /// received for redeeming a given amount of vault shares (rounded down).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `shares` - The amount of vault shares to simulate redeeming.
    fn preview_redeem(e: &Env, shares: i128) -> i128;

    /// Redeems a specific amount of vault shares for underlying assets,
    /// returning the amount of underlying assets received.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `shares` - The amount of vault shares to redeem.
    /// * `receiver` - The address that will receive the underlying assets.
    /// * `owner` - The address that owns the vault shares to be burned.
    /// * `operator` - The address performing the redemption operation.
    ///
    /// # Events
    ///
    /// * topics - `["withdraw", operator: Address, receiver: Address, owner:
    ///   Address]`
    /// * data - `[assets: i128, shares: i128]`
    fn redeem(e: &Env, shares: i128, receiver: Address, owner: Address, operator: Address) -> i128;
}
```


## Events

### Deposit Event

The deposit event is emitted when underlying assets are deposited into the vault in exchange for shares.

#### Topics:
`Address`: The address that initiated the deposit transaction.
`Address`: The address that will own the vault shares being minted.

#### Data:
`i128`: The amount of underlying assets being deposited into the vault.
`i128`: The amount of vault shares being minted in exchange for the assets.

### Withdraw Event

The withdraw event is emitted when shares are exchanged back for underlying assets and assets are withdrawn from the vault.

#### Topics:
`Address`: The address that initiated the withdrawal transaction.
`Address`: The address that will receive the underlying assets being withdrawn.
`Address`: The address that owns the vault shares being burned.

#### Data:
`i128`: The amount of underlying assets being withdrawn from the vault.
`i128`: The amount of vault shares being burned in exchange for the assets.

## Design Rationale

This standard closely follows the ERC-4626 standard for tokenized vaults, allowing seamless interoperability across ecosystems.

- ERC-4626 OpenZeppelin standard: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/interfaces/IERC4626.sol
- EIP-4626: https://eips.ethereum.org/EIPS/eip-4626

## Security Concerns

Tokenized vault contracts involve pooling user funds, making them high-value targets for attackers. We strongly encourage the community to actively discuss and identify potential attack vectors to strengthen the overall security of the tokenized vault standard on Stellar Soroban.

Addressing several key security challenges with standard vault, concerning both the concrete implementations and the standard itself:

- Overflow Protection - Using Rust checked arithmetic operations that fail on overflow.

- Rounding Errors and Precision Loss - Using Soroban fixed-point code for vault's “muldiv” operations. EVM implementation details, for reference: https://2π.com/21/muldiv/ https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol

- Authorization and Permissions (Access Control) - no access control enforced by default, authorization for the operator must be handled implementation-wise.

- Underlying Assets - Vault assets (e.g., USDC, XLM) must implement the Stellar token interface. Any standard asset should function as an underlying vault asset. Users must manage Stellar asset trustlines and approvals independently.

- Data Validation - Validation logic for i128 amounts, including zero value checks and upper/lower bounds where applicable.

- Error Handling - Expected errors handled gracefully.

- Storage Security - Enforcing specific behaviors (e.g., vault deployer setting underlying asset address only once, and/or setting admin address) versus allowing custom implementation flexibility.

- Open Vault design - By design, the standard vault implementation imposes no withdrawal or deposit time limitations, participants may transact freely unless specific implementers add restrictions.

- Asset/Share Conversion - Conversion logic should follow Ethereum (ERC-4626) counterpart implementation.

- Reentrancy Protection - Not applicable to Soroban by design.

- Token Security - Vault shares inherit all attack vectors as fungible tokens standard used (e.g., approval/allowance exploits, token balance manipulation).

- Sandwich Attacks - Theoretically possible on Stellar but significantly more difficult due to the network's unique design. Stellar's Consensus Protocol (SCP) creates substantial barriers making sandwich attacks extremely difficult in practice.

- Empty vault attack - Can be addressed by introducing virtual decimals offset (notes below).

- Unknown Risks - Additional unknown security risks may exist.

## Notes On Decimals Offset

In empty (or nearly empty) standard vaults, deposits are at high risk of being stolen through front-running with a "donation" to the vault that inflates the price of a share. This is variously known as a donation or inflation attack and is essentially a problem of slippage.

Attack Mechanism:

- Attacker deposits minimal amount (e.g. 1 token) → receives 1 share
- Attacker directly transfers large amount to vault contract → inflates share price
- Victim deposits → receives 0 shares due to rounding down
- Attacker withdraws → steals victim's deposit

Potential Solution: Configurable virtual decimals offset that allows vault implementers to set appropriate precision parameters based on their specific asset types and risk tolerance.

The decimals offset corresponds to an offset in the decimal representation between the underlying asset's decimals and the vault decimals. This offset also determines the rate of virtual shares to virtual assets in the vault, which itself determines the initial exchange rate. While not fully preventing the attack, analysis shows that the default offset (0) makes it non-profitable even if an attacker is able to capture value from multiple user deposits, as a result of the value being captured by the virtual shares (out of the attacker's donation) matching the attacker's expected gains. With a larger offset, the attack becomes orders of magnitude more expensive than it is profitable. The attack exploits share calculation mechanisms in empty or low-liquidity vaults.

References:

- https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3706
- https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3800
- https://github.com/OpenZeppelin/openzeppelin-contracts/issues/5223
- https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks
- https://docs.openzeppelin.com/contracts/5.x/erc4626
- https://forum.openzeppelin.com/t/erc4626-inflation-attack-discussion/41643/11

## Notes On Extensibility

The standard provides essential building blocks for common vault functionality while maintaining flexibility for custom implementations. Trait functions can be overridden to implement custom logic. Certain implementation decisions are intentionally left to vault implementers to ensure optimal developer experience and accommodate diverse use cases.

## Reference Implementation

The tokenized vault implementation, following this SEP standard, is available on GitHub, in the OpenZeppelin Stellar Soroban contracts library:

https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/tokens/src/fungible/extensions/vault 

Implementation specifics:

Underlying asset interactions are handled through the `TokenClient` struct, which provides functionality to query balances and decimals, as well as execute asset transfers.

Certain arithmetic operations, particularly `muldiv` calculations, are implemented based on an open-source mathematical library developed by Script3. For reference: https://github.com/script3/soroban-fixed-point-math/

OpenZeppelin’s fungible token standard implementation (SEP-41), for reference: https://github.com/OpenZeppelin/stellar-contracts/blob/main/packages/tokens/src/fungible/mod.rs 
