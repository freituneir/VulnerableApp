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
