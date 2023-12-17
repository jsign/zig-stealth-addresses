const std = @import("std");
const Endian = std.builtin.Endian;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

const Privkey = [32]u8;
const Pubkey = [33]u8;
const EthAddress = [20]u8;

// StealthAddress is an implementation of EIP-5564 for the `schemeId`=0x00 (i.e: SECP256k1, with view tags)
// In the future, we can generalize the code if more schemes are added.
pub const EIP5564 = struct {
    // `n` as defined in the spec.
    const n = @typeInfo(Pubkey).Array.len;
    const format_prefix = "st:eth:0x";
    const meta_addr_len = format_prefix.len + 2 * 2 * n; // 2 * 2 = (spending + view) * (hex)

    pub fn generateStealthAddress(sma: []const u8) !struct { stealth_address: EthAddress, ephemeral_pubkey: Secp256k1, view_tag: u8 } {
        if (sma.len != meta_addr_len) {
            return error.StealthMetaAddressWrongLength;
        }
        if (!std.mem.startsWith(u8, sma, format_prefix)) {
            return error.StealthMetaAddressWrongPrefix;
        }

        var ephemeral_priv: Privkey = undefined;
        std.crypto.random.bytes(&ephemeral_priv);
        const ephemeral_pubkey = try Secp256k1.mul(Secp256k1.basePoint, ephemeral_priv, Endian.Big);

        const spend_pubkey = try pubKeyFromHex(sma[format_prefix.len .. format_prefix.len + 2 * n]);
        const view_pubkey = try pubKeyFromHex(sma[format_prefix.len + 2 * n ..]);

        const s = try Secp256k1.mul(view_pubkey, ephemeral_priv, Endian.Big);
        var s_hashed: [Keccak256.digest_length]u8 = undefined;
        Keccak256.hash(&s.toCompressedSec1(), &s_hashed, .{});
        const view_tag = s_hashed[0];

        const pub_s_hashed = try Secp256k1.mul(Secp256k1.basePoint, s_hashed, Endian.Big);
        const pub_stealth_address_point = Secp256k1.add(spend_pubkey, pub_s_hashed);

        return .{
            .stealth_address = pointToEthAddr(pub_stealth_address_point),
            .ephemeral_pubkey = ephemeral_pubkey,
            .view_tag = view_tag,
        };
    }

    pub fn checkStealthAddress(stealth_address: EthAddress, ephemeral_pubkey: Secp256k1, viewing_key: Privkey, spending_pubkey: Secp256k1, view_tag: ?u8) !bool {
        const s = try Secp256k1.mul(ephemeral_pubkey, viewing_key, Endian.Big);
        var s_hashed: [Keccak256.digest_length]u8 = undefined;
        Keccak256.hash(&s.toCompressedSec1(), &s_hashed, .{});

        // If the view tag is provided, we do the optimized check.
        if (view_tag != null and view_tag.? != s_hashed[0])
            return false;

        const pub_s_hashed = try Secp256k1.mul(Secp256k1.basePoint, s_hashed, Endian.Big);
        const pub_stealth_address = Secp256k1.add(spending_pubkey, pub_s_hashed);
        const exp_stealth_address = pointToEthAddr(pub_stealth_address);

        return std.mem.eql(u8, &stealth_address, &exp_stealth_address);
    }

    pub fn computeStealthKey(ephemeral_pubkey: Secp256k1, viewing_key: Privkey, spending_key: Privkey) !Privkey {
        const s = try Secp256k1.mul(ephemeral_pubkey, viewing_key, Endian.Big);
        var s_hashed: [Keccak256.digest_length]u8 = undefined;
        Keccak256.hash(&s.toCompressedSec1(), &s_hashed, .{});

        const fe_spending_key = try Secp256k1.scalar.Scalar.fromBytes(spending_key, Endian.Big);
        // A direct .fromBytes(...)  errors on non-canonical representations, so we pad it to use
        // .fromBytes48(...) which does the (potentially needed) wrapping.
        var padded_s_hashed: [48]u8 = [_]u8{0} ** 48;
        @memcpy(padded_s_hashed[padded_s_hashed.len - 32 ..], &s_hashed);
        const fe_s_hashed = Secp256k1.scalar.Scalar.fromBytes48(padded_s_hashed, Endian.Big);

        return Secp256k1.scalar.Scalar.add(fe_spending_key, fe_s_hashed).toBytes(Endian.Big);
    }

    fn pubKeyFromHex(hex: []const u8) !Secp256k1 {
        var buf: [33]u8 = undefined;
        const pub_key_bytes = try std.fmt.hexToBytes(&buf, hex);
        if (pub_key_bytes.len != 33) {
            return error.PubKeyWrongLength;
        }
        return try Secp256k1.fromSec1(pub_key_bytes);
    }

    fn pointToEthAddr(pub_stealth_address: Secp256k1) EthAddress {
        var buf: [32]u8 = undefined;
        Keccak256.hash(&pub_stealth_address.toCompressedSec1(), &buf, .{});
        var stealth_addr: EthAddress = undefined;
        @memcpy(&stealth_addr, buf[12..]);

        return stealth_addr;
    }
};

test "generate and check" {
    // Spending Private Key: 0xfb6c29ca5e7f75624ff4094f83a75945f9eb891753919722f6e7597cf0899ec0
    // Viewing Private Key: 0x3884b97f3571ef8c69e5601ad0ee153478fa0f83b35e019e9d84d0f95ef002c5
    // Spending Public Key: 0x03195eec0f562a7a92665f8d085abaf84fe496fa7c53a8a898bce045266b5a33dc
    // Viewing Public Key: 0x02e075c0c31f3abf191e801a2f61d603e46293cd5ac8c4b5e11fb00624cf7fa98c
    const sma = "st:eth:0x03195eec0f562a7a92665f8d085abaf84fe496fa7c53a8a898bce045266b5a33dc02e075c0c31f3abf191e801a2f61d603e46293cd5ac8c4b5e11fb00624cf7fa98c";
    var viewing_key: Privkey = undefined;
    _ = try std.fmt.hexToBytes(&viewing_key, "3884b97f3571ef8c69e5601ad0ee153478fa0f83b35e019e9d84d0f95ef002c5");
    var spending_key: Privkey = undefined;
    _ = try std.fmt.hexToBytes(&spending_key, "fb6c29ca5e7f75624ff4094f83a75945f9eb891753919722f6e7597cf0899ec0");
    const spending_pubkey = try EIP5564.pubKeyFromHex("03195eec0f562a7a92665f8d085abaf84fe496fa7c53a8a898bce045266b5a33dc");

    // Generate stealth address for stealth meta-address.
    const ga = try EIP5564.generateStealthAddress(sma);
    // Check with view tag
    {
        const ok = try EIP5564.checkStealthAddress(ga.stealth_address, ga.ephemeral_pubkey, viewing_key, spending_pubkey, ga.view_tag);
        try std.testing.expect(ok);
    }

    // Check without view tag
    {
        const ok = try EIP5564.checkStealthAddress(ga.stealth_address, ga.ephemeral_pubkey, viewing_key, spending_pubkey, null);
        try std.testing.expect(ok);
    }

    // Check with wrong tag
    {
        const ok = try EIP5564.checkStealthAddress(ga.stealth_address, ga.ephemeral_pubkey, viewing_key, spending_pubkey, ga.view_tag +% 1);
        try std.testing.expect(!ok);
    }

    // Check with wrong spending pubkey
    {
        const wrong_spending_pubkey = try EIP5564.pubKeyFromHex("02706c71da3dd07932cd4a3c748a744f262db6a16de4df5bee58de0d03acba1260");
        const ok = try EIP5564.checkStealthAddress(ga.stealth_address, ga.ephemeral_pubkey, viewing_key, wrong_spending_pubkey, ga.view_tag +% 1);
        try std.testing.expect(!ok);
    }

    // Check with wrong viewing key
    {
        var wrong_viewing_key: Privkey = undefined;
        _ = try std.fmt.hexToBytes(&wrong_viewing_key, "cc3dc00a8a9fbd1093a43282fe7c865b64cdbfd5a8350d1432a188f0504a6700");
        const ok = try EIP5564.checkStealthAddress(ga.stealth_address, ga.ephemeral_pubkey, wrong_viewing_key, spending_pubkey, ga.view_tag +% 1);
        try std.testing.expect(!ok);
    }

    // Compute stealth key and verify with expected stealth address.
    {
        const got_privkey = try EIP5564.computeStealthKey(ga.ephemeral_pubkey, viewing_key, spending_key);
        const got_stealth_addr_point = try Secp256k1.mul(Secp256k1.basePoint, got_privkey, Endian.Big);
        const got_eth_addr = EIP5564.pointToEthAddr(got_stealth_addr_point);
        try std.testing.expect(std.mem.eql(u8, &ga.stealth_address, &got_eth_addr));
    }
}
