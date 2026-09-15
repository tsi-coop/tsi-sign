package org.tsicoop.sign.framework;

import java.security.SecureRandom;

/**
 * Generates a 5-word recovery-key passphrase and hashes it for storage -
 * the per-user "break glass" password-reset credential pattern confirmed
 * working in tsi-compass (Platform.setRecoveryKey). Only the SHA-256 hash
 * is ever persisted (platform_users.recovery_key_hash); the plaintext
 * passphrase is shown to the admin once, at generation time, and is not
 * single-use - it stays valid until replaced by another generate() call.
 */
public final class RecoveryKeyGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[] WORDS = {
            "amber", "anchor", "arrow", "ash", "aspen", "atlas", "autumn", "banjo", "basin", "beacon",
            "birch", "bloom", "blue", "boulder", "bramble", "brass", "breeze", "brook", "canyon", "cedar",
            "cinder", "clover", "cloud", "coast", "comet", "copper", "coral", "cove", "crane", "crest",
            "crimson", "crystal", "delta", "denim", "dew", "dune", "eagle", "ember", "falcon", "feather",
            "fern", "field", "flint", "forest", "forge", "fox", "garnet", "glacier", "glade", "granite",
            "grove", "gull", "harbor", "harvest", "haven", "hazel", "heron", "hollow", "honey", "indigo",
            "ivory", "ivy", "jade", "juniper", "lagoon", "lantern", "larch", "lark", "laurel", "ledge",
            "lichen", "lily", "linen", "lotus", "lynx", "maple", "marble", "marsh", "meadow", "mesa",
            "mint", "mist", "moss", "nectar", "nova", "oak", "oasis", "obsidian", "olive", "opal",
            "orchid", "otter", "pebble", "petal", "pine", "plum", "quartz", "quill", "rapid", "raven",
            "reed", "ridge", "river", "robin", "rowan", "saffron", "sage", "sail", "sand", "sapphire",
            "shale", "shore", "sienna", "silver", "slate", "sparrow", "spruce", "stone", "storm", "summit",
            "swan", "sycamore", "tarn", "teal", "thicket", "thistle", "thorn", "tide", "timber", "topaz",
            "trail", "tundra", "valley", "velvet", "violet", "vista", "walnut", "warbler", "wave", "willow",
            "wren", "zephyr"
    };

    private RecoveryKeyGenerator() {
    }

    public record GeneratedRecoveryKey(String passphrase, String passphraseHash) {
    }

    public static GeneratedRecoveryKey generate() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            if (i > 0) sb.append("-");
            sb.append(WORDS[RANDOM.nextInt(WORDS.length)]);
        }
        String passphrase = sb.toString();
        return new GeneratedRecoveryKey(passphrase, sha256Hex(passphrase));
    }

    /** Trims/lowercases before hashing so a human retyping the passphrase isn't tripped up by case/whitespace. */
    public static String sha256Hex(String passphrase) {
        return HashUtil.sha256Hex(normalize(passphrase));
    }

    private static String normalize(String passphrase) {
        return passphrase == null ? "" : passphrase.trim().toLowerCase();
    }
}
