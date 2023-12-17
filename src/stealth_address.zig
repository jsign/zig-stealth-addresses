const std = @import("std");
const Endian = std.builtin.Endian;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

// StealthAddress is an implementation of EIP-5564 for the `schemeId`=0x00 (i.e: SECP256k1, with view tags)
// In the future, we can generalize the code if more schemes are added.
pub const EIP5564 = struct {
    const Pubkey = [33]u8;
    const format_prefix = "st:eth:0x";
    // `n` as defined in the spec.
    const n = @typeInfo(Pubkey).Array.len;
    const meta_addr_len = format_prefix.len + 2 * 2 * n; // 2 * 2 = (spending + view) * (hex)

    pub fn generateStealthAddress(sma: []const u8) !struct { stealth_address: [20]u8, ephemeral_pub_key: Pubkey, view_tag: u8 } {
        if (sma.len != meta_addr_len) {
            std.log.warn("expected len {} got {}", .{ meta_addr_len, sma.len });
            return error.StealthMetaAddressWrongLength;
        }
        if (!std.mem.startsWith(u8, sma, format_prefix)) {
            return error.StealthMetaAddressWrongPrefix;
        }

        var priv_ephemeral: [32]u8 = undefined;
        std.crypto.random.bytes(&priv_ephemeral);
        const pub_ephemeral = try Secp256k1.mul(Secp256k1.basePoint, priv_ephemeral, Endian.big);

        const pub_spend = try pubKeyFromHex(sma[format_prefix.len .. format_prefix.len + 2 * n]);
        const pub_view = try pubKeyFromHex(sma[format_prefix.len + 2 * n ..]);

        const s = try Secp256k1.mul(pub_view, priv_ephemeral, Endian.big);
        var s_hashed: [Keccak256.digest_length]u8 = undefined;
        Keccak256.hash(&s.toCompressedSec1(), &s_hashed, .{});
        const view_tag = s_hashed[0];

        const pub_s_hashed = try Secp256k1.mul(Secp256k1.basePoint, s_hashed, Endian.big);
        const pub_stealth_address = Secp256k1.add(pub_spend, pub_s_hashed);

        var buf: [32]u8 = undefined;
        Keccak256.hash(&pub_stealth_address.toCompressedSec1(), &buf, .{});
        var stealth_addr: [20]u8 = undefined;
        @memcpy(&stealth_addr, buf[12..]);

        return .{
            .stealth_address = stealth_addr,
            .ephemeral_pub_key = pub_ephemeral.toCompressedSec1(),
            .view_tag = view_tag,
        };
    }

    fn pubKeyFromHex(hex: []const u8) !Secp256k1 {
        var buf: [33]u8 = undefined;
        const pub_key_bytes = try std.fmt.hexToBytes(&buf, hex);
        if (pub_key_bytes.len != 33) {
            return error.PubKeyWrongLength;
        }
        return try Secp256k1.fromSec1(pub_key_bytes);
    }
};
