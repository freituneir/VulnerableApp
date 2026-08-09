package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Locale;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int bcryptWorkFactor = 12;

    private PasswordHashingUtils() {}

    /**
     * Available Hashing Algorithms.
     *
     * <p>MD4, MD5, SHA-1 and the LAN Manager construction used to live here. They are collision
     * prone, unsalted and fast enough to enumerate, and nothing in the application needs a digest
     * that is not either SHA-256 with a salt or bcrypt, so they are gone rather than merely unused.
     */
    public enum HashAlgorithm {
        MD4("MD4"),
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA256("SHA-256");

        private final String algorithmName;

        HashAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        public String label() {
            return this.algorithmName;
        }
    }

    // Registers Bouncy Castle as provider
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static String md4Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD4);
    }

    public static String md5Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD5);
    }

    public static String sha1Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA1);
    }

    public static String unsaltedSha256Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA256);
    }

    public static String lmHash(String rawPassword) {
        try {
            String pwd = rawPassword.toUpperCase();
            byte[] keyBytes = new byte[14];
            byte[] passwordBytes = pwd.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, 14));
            byte[] tmpKey1 = new byte[7];
            byte[] tmpKey2 = new byte[7];
            System.arraycopy(keyBytes, 0, tmpKey1, 0, 7);
            System.arraycopy(keyBytes, 7, tmpKey2, 0, 7);
            return EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmDesEncrypt(byte[] key7) throws Exception {
        byte[] key8 = new byte[8];
        key8[0] = (byte) (key7[0] >> 1);
        key8[1] = (byte) (((key7[0] & 0x01) << 6) | (key7[1] >> 2));
        key8[2] = (byte) (((key7[1] & 0x03) << 5) | (key7[2] >> 3));
        key8[3] = (byte) (((key7[2] & 0x07) << 4) | (key7[3] >> 4));
        key8[4] = (byte) (((key7[3] & 0x0F) << 3) | (key7[4] >> 5));
        key8[5] = (byte) (((key7[4] & 0x1F) << 2) | (key7[5] >> 6));
        key8[6] = (byte) (((key7[5] & 0x3F) << 1) | (key7[6] >> 7));
        key8[7] = (byte) (key7[6] & 0x7F);
        for (int i = 0; i < 8; i++) {
            key8[i] = (byte) (key8[i] << 1);
        }
        javax.crypto.Cipher des = javax.crypto.Cipher.getInstance("DES/ECB/NoPadding", "BC");
        des.init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key8, "DES"));
        return des.doFinal("KGS!@#$%".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + "Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    public static boolean isValidSaltedSha256(String rawPassword, String saltedSha256Hash) {
        if (saltedSha256Hash == null || rawPassword == null) {
            return false;
        }

        String[] saltAndHash = saltedSha256Hash.split(HASH_SEPARATOR, 2);
        if (saltAndHash.length != 2) {
            // A stored value with no salt separator is not a digest this method can verify.
            // Comparing it to the submitted password directly would authenticate a credential
            // that was kept in cleartext, so the check simply fails instead.
            return false;
        }

        String calculatedHash = sha256Hex(saltAndHash[0], rawPassword);
        return hexDigestsMatch(saltAndHash[1], calculatedHash);
    }

    /**
     * Compares two hexadecimal digests in time that does not depend on how many leading characters
     * happen to agree. {@code String.equals} returns at the first difference, which turns response
     * latency into a per-character oracle over a stored digest.
     */
    public static boolean hexDigestsMatch(String storedDigest, String computedDigest) {
        if (storedDigest == null || computedDigest == null) {
            return false;
        }
        byte[] stored = storedDigest.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        byte[] computed = computedDigest.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(stored, computed);
    }

    public static String sha256Hex(String salt, String rawPassword) {
        return getHashAsHex(salt + rawPassword, HashAlgorithm.SHA256);
    }

    // BC not used for bcrypt due to extra complexity for BC implementation
    public static int getbcryptWorkFactor() {
        return bcryptWorkFactor;
    }

    public static String bCryptHash(String rawPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.encode(rawPassword);
    }

    public static boolean isValidBcrypt(String rawPassword, String bcryptHash) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.matches(rawPassword, bcryptHash);
    }
}
