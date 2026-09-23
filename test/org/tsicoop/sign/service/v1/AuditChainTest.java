package org.tsicoop.sign.service.v1;

import org.junit.Test;

import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class AuditChainTest {

    private static final Instant T = Instant.parse("2026-09-23T15:54:41.221786Z");

    private static String hash(String prev, String event, String ip) {
        return AuditLogRepository.entryHash(prev, "a1", "app1", "doc1", event, "SYSTEM", null, ip, "ua", T);
    }

    @Test
    public void hashIsDeterministicAndHex() {
        assertEquals(hash("", "SEALED", "1.2.3.4"), hash("", "SEALED", "1.2.3.4"));
        assertEquals(64, hash("", "SEALED", "1.2.3.4").length());
    }

    @Test
    public void anyFieldOrPredecessorChangeChangesTheHash() {
        String base = hash("p", "SEALED", "1.2.3.4");
        assertNotEquals(base, hash("q", "SEALED", "1.2.3.4"));
        assertNotEquals(base, hash("p", "ESIGN_COMPLETED", "1.2.3.4"));
        assertNotEquals(base, hash("p", "SEALED", "1.2.3.5"));
        assertNotEquals(base, AuditLogRepository.entryHash("p", "a1", "app1", "doc1", "SEALED", "SYSTEM", null, "1.2.3.4", "ua", T.plusNanos(1000)));
    }

    @Test
    public void valuesCannotBeShiftedBetweenAdjacentFields() {
        // Without length prefixes ("ab","c") and ("a","bc") would concatenate identically.
        String a = AuditLogRepository.entryHash("", "id", "app", "ab", "c", "SYSTEM", null, null, null, T);
        String b = AuditLogRepository.entryHash("", "id", "app", "a", "bc", "SYSTEM", null, null, null, T);
        assertNotEquals(a, b);
    }
}
