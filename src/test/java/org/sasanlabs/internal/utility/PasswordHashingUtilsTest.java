package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("SHA-256: Should generate a correct salted hash")
    void sha256Hash_CorrectHex() {
        // Known SHA-256 hash for "salt" + "password"
        String expected = "13601bda4ea78e55a07b98866d2be6be0744e3866f13c00c811cab608a28f322";
        assertEquals(expected, PasswordHashingUtils.sha256Hex("salt", "password"));
        assertNotEquals(expected, PasswordHashingUtils.sha256Hex("othersalt", "password"));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123";
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("SHA-256: A stored value without a salt separator must never authenticate")
    void isValidSaltedSha256_RejectsCleartextStoredValue() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("hunter2", "hunter2"));
    }

    @Test
    @DisplayName("Digest comparison: Should fold case and reject mismatches and nulls")
    void hexDigestsMatch_Comparison() {
        assertTrue(PasswordHashingUtils.hexDigestsMatch("ABCdef01", "abcdef01"));
        assertFalse(PasswordHashingUtils.hexDigestsMatch("abcdef01", "abcdef02"));
        assertFalse(PasswordHashingUtils.hexDigestsMatch("abcdef01", "abcdef0"));
        assertFalse(PasswordHashingUtils.hexDigestsMatch(null, "abcdef01"));
        assertFalse(PasswordHashingUtils.hexDigestsMatch("abcdef01", null));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword";
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
