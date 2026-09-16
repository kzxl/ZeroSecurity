using System;
using System.Numerics;

namespace ZeroSecurity.Crypto;

/// <summary>
/// Pure C# RFC 8439 Authenticated Encryption with Associated Data (AEAD) using ChaCha20 and Poly1305.
/// Designed for zero-allocation quarantine file encryption and confidential ZeroWire frame payloads.
/// </summary>
public static class ChaCha20Poly1305
{
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;

    private static readonly uint[] Sigma = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 }; // "expand 32-byte k"

    /// <summary>
    /// Encrypts plaintext using ChaCha20-Poly1305 AEAD.
    /// </summary>
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));
        if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes.", nameof(nonce));
        if (ciphertext.Length < plaintext.Length) throw new ArgumentException("Ciphertext span too small.", nameof(ciphertext));
        if (tag.Length < TagSize) throw new ArgumentException($"Tag span must be at least {TagSize} bytes.", nameof(tag));

        // 1. Generate Poly1305 key using ChaCha20 block 0
        Span<byte> polyKeyBlock = stackalloc byte[64];
        ChaCha20Block(key, nonce, 0, polyKeyBlock);
        ReadOnlySpan<byte> polyKey = polyKeyBlock.Slice(0, 32);

        // 2. Encrypt plaintext starting with ChaCha20 block 1
        ChaCha20Process(key, nonce, 1, plaintext, ciphertext);

        // 3. Compute Poly1305 MAC over (AAD || padding || Ciphertext || padding || len(AAD) || len(Ciphertext))
        ComputeTag(polyKey, associatedData, ciphertext.Slice(0, plaintext.Length), tag.Slice(0, TagSize));
    }

    /// <summary>
    /// Decrypts ciphertext and verifies Poly1305 authentication tag.
    /// Returns true if tag is valid and plaintext was written; false if authentication failed.
    /// </summary>
    public static bool Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));
        if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes.", nameof(nonce));
        if (tag.Length < TagSize) throw new ArgumentException($"Tag must be at least {TagSize} bytes.", nameof(tag));
        if (plaintext.Length < ciphertext.Length) throw new ArgumentException("Plaintext span too small.", nameof(plaintext));

        // 1. Generate Poly1305 key
        Span<byte> polyKeyBlock = stackalloc byte[64];
        ChaCha20Block(key, nonce, 0, polyKeyBlock);
        ReadOnlySpan<byte> polyKey = polyKeyBlock.Slice(0, 32);

        // 2. Verify MAC
        Span<byte> expectedTag = stackalloc byte[TagSize];
        ComputeTag(polyKey, associatedData, ciphertext, expectedTag);

        if (!ConstantTimeEquals(tag.Slice(0, TagSize), expectedTag))
        {
            plaintext.Slice(0, ciphertext.Length).Clear();
            return false;
        }

        // 3. Decrypt
        ChaCha20Process(key, nonce, 1, ciphertext, plaintext);
        return true;
    }

    private static void ChaCha20Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint initialCounter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> keyStream = stackalloc byte[64];
        uint counter = initialCounter;
        int offset = 0;

        while (offset < input.Length)
        {
            ChaCha20Block(key, nonce, counter++, keyStream);
            int take = Math.Min(64, input.Length - offset);

            for (int i = 0; i < take; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ keyStream[i]);
            }

            offset += take;
        }
    }

    private static void ChaCha20Block(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<byte> output)
    {
        Span<uint> state = stackalloc uint[16];

        // Constants
        state[0] = Sigma[0];
        state[1] = Sigma[1];
        state[2] = Sigma[2];
        state[3] = Sigma[3];

        // Key
        for (int i = 0; i < 8; i++)
        {
            state[4 + i] = ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        }

        // Counter
        state[12] = counter;

        // Nonce
        for (int i = 0; i < 3; i++)
        {
            state[13 + i] = ReadUInt32LittleEndian(nonce.Slice(i * 4, 4));
        }

        Span<uint> working = stackalloc uint[16];
        state.CopyTo(working);

        // 20 rounds (10 column + 10 diagonal)
        for (int i = 0; i < 10; i++)
        {
            QR(ref working[0], ref working[4], ref working[8], ref working[12]);
            QR(ref working[1], ref working[5], ref working[9], ref working[13]);
            QR(ref working[2], ref working[6], ref working[10], ref working[14]);
            QR(ref working[3], ref working[7], ref working[11], ref working[15]);

            QR(ref working[0], ref working[5], ref working[10], ref working[15]);
            QR(ref working[1], ref working[6], ref working[11], ref working[12]);
            QR(ref working[2], ref working[7], ref working[8], ref working[13]);
            QR(ref working[3], ref working[4], ref working[9], ref working[14]);
        }

        for (int i = 0; i < 16; i++)
        {
            WriteUInt32LittleEndian(working[i] + state[i], output.Slice(i * 4, 4));
        }
    }

    private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d = RotateLeft(d ^ a, 16);
        c += d; b = RotateLeft(b ^ c, 12);
        a += b; d = RotateLeft(d ^ a, 8);
        c += d; b = RotateLeft(b ^ c, 7);
    }

    private static uint RotateLeft(uint v, int c) => (v << c) | (v >> (32 - c));

    private static void ComputeTag(ReadOnlySpan<byte> polyKey, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
    {
        // r = key[0..15] clamped, s = key[16..31]
        byte[] rBytes = new byte[17];
        polyKey.Slice(0, 16).CopyTo(rBytes);
        rBytes[3] &= 15;
        rBytes[7] &= 15;
        rBytes[11] &= 15;
        rBytes[15] &= 15;
        rBytes[4] &= 252;
        rBytes[8] &= 252;
        rBytes[12] &= 252;
        rBytes[16] = 0x00;
        BigInteger r = new BigInteger(rBytes);

        byte[] sBytes = new byte[17];
        polyKey.Slice(16, 16).CopyTo(sBytes);
        sBytes[16] = 0x00; // Force positive in standard BigInteger(byte[])
        BigInteger s = new BigInteger(sBytes);
        BigInteger p = (BigInteger.One << 130) - 5;
        BigInteger a = BigInteger.Zero;

        // Process AAD
        ProcessPolyData(aad, ref a, r, p);

        // Process Ciphertext
        ProcessPolyData(ciphertext, ref a, r, p);

        // Process Lengths
        byte[] lenBlock = new byte[16];
        BitConverter.GetBytes((ulong)aad.Length).CopyTo(lenBlock, 0);
        BitConverter.GetBytes((ulong)ciphertext.Length).CopyTo(lenBlock, 8);

        byte[] lenBlockWithTerm = new byte[17];
        Array.Copy(lenBlock, lenBlockWithTerm, 16);
        lenBlockWithTerm[16] = 0x01; // padding marker

        BigInteger n = new BigInteger(lenBlockWithTerm);
        a = ((a + n) * r) % p;

        a = (a + s) % (BigInteger.One << 128);

        byte[] tagBytes = a.ToByteArray();
        tag.Clear();
        int copyLen = Math.Min(TagSize, tagBytes.Length);
        tagBytes.AsSpan(0, copyLen).CopyTo(tag);
    }

    private static void ProcessPolyData(ReadOnlySpan<byte> data, ref BigInteger a, BigInteger r, BigInteger p)
    {
        int offset = 0;
        while (offset < data.Length)
        {
            int take = Math.Min(16, data.Length - offset);
            byte[] block = new byte[take + 1];
            data.Slice(offset, take).CopyTo(block);
            block[take] = 0x01; // append 1 bit (0x01 byte)

            BigInteger n = new BigInteger(block);
            a = ((a + n) * r) % p;

            offset += take;
        }
    }

    private static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> s) =>
        (uint)s[0] | ((uint)s[1] << 8) | ((uint)s[2] << 16) | ((uint)s[3] << 24);

    private static void WriteUInt32LittleEndian(uint val, Span<byte> dest)
    {
        dest[0] = (byte)val;
        dest[1] = (byte)(val >> 8);
        dest[2] = (byte)(val >> 16);
        dest[3] = (byte)(val >> 24);
    }
}
