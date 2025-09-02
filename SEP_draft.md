## Preamble

```
SEP: TBD
Title: Tokenized Vault Standard SEP
Author: OpenZeppelin <@OpenZeppelin>, Sentinel <@SentinelFi>
Track: Standard
Status: Draft
Created: 2025-09-02
Updated: 2025-09-02
Version: 0.1.0
Discussion: link
```

## Summary

This SEP introduces a standard for tokenized vault contracts on Stellar Soroban. A tokenized vault is a smart contract and DeFi primitive that pools funds by allowing users to deposit underlying assets (such as XLM or USDC) and mint a corresponding amount of shares (vault tokens) in return, representing their proportional ownership of the total vault pool. The assets locked in a vault can be utilized by the smart contract logic for yield generation, lending and borrowing, staking, insurance, prediction markets, and other use cases. When users withdraw their assets, their corresponding share tokens are burned.

## Dependencies

Underlying Asset Standard: The tokenized vault utilizes Soroban smart contracts that implement the "TokenInterface" standard. Asset interactions are handled through the "TokenClient" struct, which provides functionality to query balances and decimals, as well as execute asset transfers.
Reference: https://github.com/SentinelFi/stellar-protocol/blob/master/ecosystem/sep-0041.md (Soroban Token Interface)

Shares Token Standard: The tokenized vault implements a fungible token standard similar to ERC-20, extending OpenZeppelin's fungible token contract.
Reference: https://github.com/OpenZeppelin/stellar-contracts/blob/main/packages/tokens/src/fungible/storage.rs

Mathematical Operations: Certain arithmetic operations, particularly "muldiv" calculations, are implemented based on an open-source mathematical library developed by Script3.
Reference: https://github.com/script3/soroban-fixed-point-math/

## Motivation

While the ERC-4626 standard has long existed in the EVM ecosystem, there is currently no standard defining tokenized vaults in Stellar Soroban. This standard is proposed to enable consistent integrations between DeFi projects, making it easier for protocols to interoperate and for developers to build composable DeFi applications using vaults. By providing well-architected building blocks that address common architectural challenges, this standard aims to reduce development time and help avoid common implementation pitfalls that arise in tokenized asset management use cases.

## Abstract

The tokenized vault standard provides essential building blocks including:
- Standard vault interface (trait), storage, events, and error handling
- Share token issuance operations
- Core vault operation logic (deposit/withdraw/mint/redeem)
- Conversion mechanisms for asset-to-shares and shares-to-asset calculations
- Mathematical safeguards including rounding logic and phantom overflow protection
- Virtual decimals offset implementation to mitigate empty vault attack vulnerabilities
- Extensive documentation and comprehensive test coverage

The vault contract extends the fungible token standard for share tokenization. Any additional extensions implemented alongside this standard affect the "shares" token represented by this contract, not the underlying "assets" token, which remains an independent contract.

The standard vault building blocks will be included in the OpenZeppelin Stellar Soroban contracts library (https://github.com/OpenZeppelin/stellar-contracts), enabling Soroban developers and vault implementers to leverage the provided building blocks, override specific functionality as needed, or build custom implementations based on this foundation.

## Interface

```rust
/// Vault Trait for Fungible Token
///
/// The `FungibleVault` trait implements the ERC-4626 tokenized vault standard,
/// enabling fungible tokens to represent shares in an underlying asset pool.
/// This extension allows users to deposit underlying assets in exchange for
/// vault shares, and later redeem those shares for the underlying assets.
///
/// The vault maintains a conversion rate between shares and assets based on
/// the total supply of shares and total assets held by the vault contract.
///
/// # Design Overview
///
/// This trait provides both high-level and low-level functions:
///
/// - **High-Level Functions**: Include necessary checks, validations, and event
///   emissions for secure vault operations.
/// - **Low-Level Functions**: Offer granular control for custom workflows
///   requiring manual authorization handling.
///
/// # Security Considerations
///
/// ⚠️ **IMPORTANT**: Most low-level functions for this trait bypass
/// authorization checks by design. It is the implementer's responsibility to
/// add appropriate access controls, typically by combining with Ownable or
/// Access Control patterns.
///
/// # Compatibility
///
/// This implementation follows the ERC-4626 standard for tokenized vaults,
/// providing familiar interfaces for Ethereum developers while leveraging
/// Stellar's unique capabilities.
pub trait FungibleVault: FungibleToken<ContractType = Vault> {
    /// Returns the address of the underlying asset that the vault manages.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultAssetAddressNotSet`] - When the vault's
    ///   underlying asset address has not been initialized.
    fn query_asset(e: &Env) -> Address;

    /// Returns the total amount of underlying assets held by the vault.
    ///
    /// This represents the vault's balance of the underlying asset, which
    /// determines the conversion rate between shares and assets.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultAssetAddressNotSet`] - When the vault's
    ///   underlying asset address has not been initialized.
    fn total_assets(e: &Env) -> i128;

    /// Converts an amount of underlying assets to the equivalent amount of
    /// vault shares (rounded down).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `assets` - The amount of underlying assets to convert.
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultInvalidAssetsAmount`] - When assets < 0.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
    fn convert_to_shares(e: &Env, assets: i128) -> i128;

    /// Converts an amount of vault shares to the equivalent amount of
    /// underlying assets (rounded down).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `shares` - The amount of vault shares to convert.
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultInvalidSharesAmount`] - When shares < 0.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
    fn convert_to_assets(e: &Env, shares: i128) -> i128;

    /// Returns the maximum amount of underlying assets that can be deposited
    /// for the given receiver address (currently `i128::MAX`).
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
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultInvalidAssetsAmount`] - When assets < 0.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
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
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultExceededMaxDeposit`] - When attempting to
    ///   deposit more assets than the maximum allowed for the receiver.
    /// * [`FungibleTokenError::VaultInvalidAssetsAmount`] - When `assets < 0`.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
    ///
    /// # Events
    ///
    /// * topics - `["deposit", operator: Address, receiver: Address]`
    /// * data - `[assets: i128, shares: i128]`
    ///
    /// # Security Warning
    ///
    /// ⚠️ SECURITY RISK: This function has NO AUTHORIZATION CONTROLS ⚠️
    ///
    /// Authorization for the operator must be handled at a higher level.
    fn deposit(e: &Env, assets: i128, receiver: Address, operator: Address) -> i128;

    /// Returns the maximum amount of vault shares that can be minted
    /// for the given receiver address (currently `i128::MAX`).
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
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultInvalidSharesAmount`] - When shares < 0.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
    fn preview_mint(e: &Env, shares: i128) -> i128;

    /// Mints a specific amount of vault shares to the receiver by depositing
    /// the required amount of underlying assets, returning the amount of assets
    /// deposited.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `shares` - The amount of vault shares to mint.
    /// * `receiver` - The address that will receive the minted vault shares.
    /// * `operator` - The address performing the mint operation.
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultExceededMaxMint`] - When attempting to mint
    ///   more shares than the maximum allowed for the receiver.
    /// * [`FungibleTokenError::VaultInvalidSharesAmount`] - When `shares < 0`.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
    ///
    /// # Events
    ///
    /// * topics - `["deposit", operator: Address, receiver: Address]`
    /// * data - `[assets: i128, shares: i128]`
    ///
    /// # Security Warning
    ///
    /// ⚠️ SECURITY RISK: This function has NO AUTHORIZATION CONTROLS ⚠️
    ///
    /// Authorization for the operator must be handled at a higher level.
    fn mint(e: &Env, shares: i128, receiver: Address, operator: Address) -> i128;

    /// Returns the maximum amount of underlying assets that can be
    /// withdrawn by the given owner, limited by their vault share balance.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `owner` - The address that owns the vault shares.
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultInvalidSharesAmount`] - When shares < 0.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
    fn max_withdraw(e: &Env, owner: Address) -> i128;

    /// Simulates and returns the amount of vault shares that would be burned
    /// to withdraw a given amount of underlying assets (rounded up).
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `assets` - The amount of underlying assets to simulate withdrawing.
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultInvalidAssetsAmount`] - When assets < 0.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
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
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultExceededMaxWithdraw`] - When attempting to
    ///   withdraw more assets than the maximum allowed for the owner.
    ///
    /// # Events
    ///
    /// * topics - `["withdraw", operator: Address, receiver: Address, owner:
    ///   Address]`
    /// * data - `[assets: i128, shares: i128]`
    ///
    /// # Security Warning
    ///
    /// ⚠️ SECURITY RISK: This function has NO AUTHORIZATION CONTROLS ⚠️
    ///
    /// Authorization for the operator must be handled at a higher level.
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
    ///
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultInvalidSharesAmount`] - When shares < 0.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
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
    /// # Errors
    ///
    /// * [`FungibleTokenError::VaultExceededMaxRedeem`] - When attempting to
    ///   redeem more shares than the maximum allowed for the owner.
    /// * [`FungibleTokenError::VaultInvalidSharesAmount`] - When `shares < 0`.
    /// * [`FungibleTokenError::MathOverflow`] - When mathematical operations
    ///   result in overflow.
    ///
    /// # Events
    ///
    /// * topics - `["withdraw", operator: Address, receiver: Address, owner:
    ///   Address]`
    /// * data - `[assets: i128, shares: i128]`
    ///
    /// # Security Warning
    ///
    /// ⚠️ SECURITY RISK: This function has NO AUTHORIZATION CONTROLS ⚠️
    ///
    /// Authorization for the operator must be handled at a higher level.
    fn redeem(e: &Env, shares: i128, receiver: Address, owner: Address, operator: Address) -> i128;
}
```

## Events

```rust
/// Emits an event when underlying assets are deposited into the vault in
/// exchange for shares.
///
/// # Arguments
///
/// * `e` - Access to Soroban environment.
/// * `sender` - The address that initiated the deposit transaction.
/// * `owner` - The address that will own the vault shares being minted.
/// * `assets` - The amount of underlying assets being deposited into the vault.
/// * `shares` - The amount of vault shares being minted in exchange for the
///   assets.
///
/// # Events
///
/// * topics - `["deposit", sender: Address, owner: Address]`
/// * data - `[assets: i128, shares: i128]`
pub fn emit_deposit(e: &Env, sender: &Address, owner: &Address, assets: i128, shares: i128) {
    let topics = (symbol_short!("deposit"), sender, owner);
    e.events().publish(topics, (assets, shares));
}

/// Emits an event when shares are exchanged back for underlying assets and
/// assets are withdrawn from the vault.
///
/// # Arguments
///
/// * `e` - Access to Soroban environment.
/// * `sender` - The address that initiated the withdrawal transaction.
/// * `receiver` - The address that will receive the underlying assets being
///   withdrawn.
/// * `owner` - The address that owns the vault shares being burned.
/// * `assets` - The amount of underlying assets being withdrawn from the vault.
/// * `shares` - The amount of vault shares being burned in exchange for the
///   assets.
///
/// # Events
///
/// * topics - `["withdraw", sender: Address, receiver: Address, owner:
///   Address]`
/// * data - `[assets: i128, shares: i128]`
pub fn emit_withdraw(
    e: &Env,
    sender: &Address,
    receiver: &Address,
    owner: &Address,
    assets: i128,
    shares: i128,
) {
    let topics = (symbol_short!("withdraw"), sender, receiver, owner);
    e.events().publish(topics, (assets, shares));
}
```

## Design Rationale

This standard closely follows the ERC-4626 standard for tokenized vaults, providing familiar interfaces for Ethereum developers while leveraging Stellar's unique capabilities.
- ERC-4626 OpenZeppelin standard: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/interfaces/IERC4626.sol
- EIP-4626: https://eips.ethereum.org/EIPS/eip-4626

## Security Concerns

Tokenized vault contracts involve pooling user funds, making them high-value targets for attackers. We strongly encourage the community to actively discuss and identify potential attack vectors to strengthen the overall security of tokenized vault standard on Stellar Soroban.

Addressing several key security challenges with standard vault:

- Overflow Protection - Using Rust checked arithmetic operations that fail on overflow.

- Rounding Errors and Precision Loss - Using Soroban fixed-point math library code for vault's muldiv operations. EVM implementation details: https://2π.com/21/muldiv/ https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol

- Authorization and Permissions (Access Control) - no access control enforced by default, authorization for the operator must be handled at a higher level.

- Underlying Assets - Vault assets (e.g., USDC, XLM) must implement the Stellar token interface. Soroban's TokenClient handles token contract calls. Any standard asset should function as an underlying vault asset. Users must manage Stellar asset trustlines and approvals independently.

- Data Validation - Validation logic for i128 amounts, including zero value checks and upper/lower bounds where applicable.

- Error Handling - Expected errors handled gracefully.

- Storage Security - Enforcing specific behaviors (e.g., vault deployer setting underlying asset address only once in constructor, and/or setting admin address) versus allowing custom implementation flexibility. Currently, it is the latter.

- Open Vault design - By design, the standard vault implementation imposes no withdrawal or deposit time limitations, participants may transact freely unless specific implementers add restrictions.

- Asset/Share Conversion - Conversion logic follows Ethereum (ERC-4626) counterpart implementation.

- Reentrancy Protection - Not applicable to Soroban by design. Current vault implementation contains no external calls unless developers add custom logic.

- Token Security - Vault shares inherit all attack vectors as fungible tokens standard used (e.g., approval/allowance exploits, token balance manipulation).

- Sandwich Attacks - Theoretically possible on Stellar but significantly more difficult due to the network's unique design. Stellar's Consensus Protocol (SCP) creates substantial barriers making sandwich attacks extremely difficult in practice.

- Empty vault attack - Addressed by introducing virtual decimals offset.

- Security Audit - Professional security audit required upon implementation.

- Unknown Risks - Additional unknown security risks may exist.

## Notes On Decimals Offset

In empty (or nearly empty) standard vaults, deposits are at high risk of being stolen through frontrunning with a "donation" to the vault that inflates the price of a share. This is variously known as a donation or inflation attack and is essentially a problem of slippage.

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
- https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC4626.sol#L279
- https://forum.openzeppelin.com/t/erc4626-inflation-attack-discussion/41643/11

## Notes On Extensibility 

The standard provides essential building blocks for common vault functionality while maintaining flexibility for custom implementations. Trait functions can be overridden to implement custom logic, or developers can use the default implementations provided. Certain implementation decisions are intentionally left to vault implementers to ensure optimal developer experience and accommodate diverse use cases.

## Reference Implementation

A draft implementation is currently available as a pull request on GitHub, with merge into the OpenZeppelin Stellar Soroban contracts library planned for the near future.

https://github.com/OpenZeppelin/stellar-contracts/pull/346/files
