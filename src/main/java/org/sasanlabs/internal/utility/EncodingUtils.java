package org.sasanlabs.internal.utility;

public class EncodingUtils {
    public static String bytesToHex(byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte value : data) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    // encodeBase64 was the helper the CryptographicFailures LEVEL_2 vault was built on: it stored
    // Base64 of the password and called it encryption. That level now stores a one-way digest, the
    // helper has no callers left, and leaving a "make it look encoded" utility in a shared package
    // is an invitation to reintroduce the same mistake.
}
