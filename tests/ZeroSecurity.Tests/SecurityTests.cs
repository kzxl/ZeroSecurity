using System;
using System.Text;
using Xunit;
using ZeroSecurity.Anomaly;
using ZeroSecurity.Crypto;
using ZeroSecurity.Hashing;
using ZeroSecurity.Matching;

namespace ZeroSecurity.Tests;

public class SecurityTests
{
    [Fact]
    public void FastSha256_KnownVectors_MatchExpectations()
    {
        // Vector: "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        byte[] abc = Encoding.UTF8.GetBytes("abc");
        string hash = FastSha256.HashHex(abc);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash);

        // Vector: "" (empty) -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        string emptyHash = FastSha256.HashHex(ReadOnlySpan<byte>.Empty);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", emptyHash);
    }

    [Fact]
    public void Blake3_SingleChunkAndMultiChunk_ProducesConsistent32ByteHashes()
    {
        // Empty string
        string emptyHash = Blake3.HashHex(ReadOnlySpan<byte>.Empty);
        Assert.Equal(64, emptyHash.Length);

        // Single chunk (<1024 bytes)
        byte[] shortData = Encoding.UTF8.GetBytes("ZeroUniverse Sovereign Security Engine");
        string shortHash = Blake3.HashHex(shortData);
        Assert.Equal(64, shortHash.Length);
        Assert.NotEqual(emptyHash, shortHash);

        // Multi chunk (>1024 bytes)
        byte[] largeData = new byte[2500];
        for (int i = 0; i < largeData.Length; i++) largeData[i] = (byte)(i & 0xFF);
        string largeHash = Blake3.HashHex(largeData);
        Assert.Equal(64, largeHash.Length);
        Assert.NotEqual(shortHash, largeHash);
    }

    [Fact]
    public void SsdeepFuzzyHash_SimilarInputs_YieldsHighScore()
    {
        byte[] original = Encoding.UTF8.GetBytes(new string('A', 500) + "malicious_payload_1" + new string('B', 500));
        byte[] modified = Encoding.UTF8.GetBytes(new string('A', 500) + "malicious_payload_2" + new string('B', 500));
        byte[] different = Encoding.UTF8.GetBytes(new string('X', 1000));

        string hash1 = SsdeepFuzzyHash.Compute(original);
        string hash2 = SsdeepFuzzyHash.Compute(modified);
        string hash3 = SsdeepFuzzyHash.Compute(different);

        Assert.NotEmpty(hash1);
        Assert.NotEmpty(hash2);
        Assert.NotEmpty(hash3);

        int similarity = SsdeepFuzzyHash.Compare(hash1, hash2);
        int diffScore = SsdeepFuzzyHash.Compare(hash1, hash3);

        Assert.True(similarity > 50, $"Expected similarity > 50, got {similarity}");
        Assert.True(diffScore < similarity, $"Expected different score < similarity, got {diffScore} vs {similarity}");
    }

    [Fact]
    public void BloomFilter_AddAndContains_WorksWithSerialization()
    {
        var filter = new BloomFilter(1000, 0.01);
        filter.Add("malware_hash_1");
        filter.Add("malware_hash_2");
        filter.Add("c2.evil-domain.com");

        Assert.True(filter.Contains("malware_hash_1"));
        Assert.True(filter.Contains("malware_hash_2"));
        Assert.True(filter.Contains("c2.evil-domain.com"));
        Assert.False(filter.Contains("benign_application.exe"));

        // Test serialization roundtrip
        byte[] bytes = filter.ToByteArray();
        var restored = BloomFilter.FromByteArray(bytes);

        Assert.True(restored.Contains("malware_hash_1"));
        Assert.True(restored.Contains("c2.evil-domain.com"));
        Assert.False(restored.Contains("benign_application.exe"));
    }

    [Fact]
    public void AhoCorasick_MultiPattern_FindsKeywordsSimultaneously()
    {
        var patterns = new[] { "powershell", "-enc", "mimikatz", "cmd.exe" };
        var matcher = new AhoCorasick(patterns);

        string commandLine = "C:\\Windows\\System32\\cmd.exe /c powershell.exe -enc aW1wb3J0...";
        var matches = matcher.Search(commandLine);

        Assert.Contains(matches, m => m.Keyword == "cmd.exe");
        Assert.Contains(matches, m => m.Keyword == "powershell");
        Assert.Contains(matches, m => m.Keyword == "-enc");
        Assert.DoesNotContain(matches, m => m.Keyword == "mimikatz");
    }

    [Fact]
    public void RadixIpTrie_SubnetLookup_ReturnsCorrectThreatLabel()
    {
        var trie = new RadixIpTrie();
        trie.AddCidr("185.220.101.0/24", "Tor Exit Node");
        trie.AddCidr("10.0.0.0/8", "Internal RFC1918");
        trie.AddCidr("192.168.1.100/32", "Compromised Host");

        Assert.True(trie.TryMatch("185.220.101.45", out var tag1));
        Assert.Equal("Tor Exit Node", tag1);

        Assert.True(trie.TryMatch("10.20.30.40", out var tag2));
        Assert.Equal("Internal RFC1918", tag2);

        Assert.True(trie.TryMatch("192.168.1.100", out var tag3));
        Assert.Equal("Compromised Host", tag3);

        Assert.False(trie.TryMatch("8.8.8.8", out _));
    }

    [Fact]
    public void ShannonEntropy_DetectsRandomOrEncryptedData()
    {
        // 1. Uniform identical data -> 0 entropy
        byte[] uniform = new byte[1000];
        double e1 = ShannonEntropy.Calculate(uniform);
        Assert.Equal(0.0, e1, 3);
        Assert.False(ShannonEntropy.IsLikelyEncryptedOrPacked(uniform));

        // 2. Encrypted / Pseudo-random data -> High entropy (> 7.5)
        byte[] randomData = new byte[1000];
        var rng = new Random(42);
        rng.NextBytes(randomData);
        double e2 = ShannonEntropy.Calculate(randomData);
        Assert.True(e2 > 7.5, $"Expected entropy > 7.5, got {e2}");
        Assert.True(ShannonEntropy.IsLikelyEncryptedOrPacked(randomData));
    }

    [Fact]
    public void WelfordStats_OnlineZScore_DetectsOutliers()
    {
        var stats = new WelfordStats();

        // Baseline: normal distribution around 10.0
        for (int i = 0; i < 50; i++)
        {
            stats.Update(10.0 + (i % 5) * 0.1);
        }

        Assert.True(stats.Mean >= 9.9 && stats.Mean <= 10.3);
        Assert.False(stats.IsAnomaly(10.2));

        // Sudden massive anomaly (e.g. process spawned 1000 child processes or burst outbound traffic)
        Assert.True(stats.IsAnomaly(100.0, zThreshold: 3.0));
    }

    [Fact]
    public void ChaCha20Poly1305_EncryptDecryptRoundtrip_SucceedsAndDetectsTampering()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = Encoding.UTF8.GetBytes("SystemMetadata");
        byte[] plaintext = Encoding.UTF8.GetBytes("TopSecretQuarantineExecutablePayloadContent");

        for (int i = 0; i < 32; i++) key[i] = (byte)(i + 1);
        for (int i = 0; i < 12; i++) nonce[i] = (byte)(i + 10);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        // 1. Encrypt
        ChaCha20Poly1305.Encrypt(key, nonce, aad, plaintext, ciphertext, tag);
        Assert.NotEqual(plaintext, ciphertext);

        // 2. Decrypt & Verify
        byte[] decrypted = new byte[plaintext.Length];
        bool ok = ChaCha20Poly1305.Decrypt(key, nonce, aad, ciphertext, tag, decrypted);
        Assert.True(ok);
        Assert.Equal(plaintext, decrypted);

        // 3. Tamper with ciphertext -> verification must fail
        ciphertext[0] ^= 0xFF;
        byte[] failBuffer = new byte[plaintext.Length];
        bool tamperOk = ChaCha20Poly1305.Decrypt(key, nonce, aad, ciphertext, tag, failBuffer);
        Assert.False(tamperOk);
    }
}
