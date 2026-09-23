package org.tsicoop.sign.esign;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ESignAdapterRegistryTest {

    @Test
    public void knownProvidersAreRegisteredAndSealProviderIdsAreNot() {
        for (String id : new String[]{"sandbox", "cca_generic", "emudhra", "cdac", "protean", "vsign"}) {
            assertTrue(id, ESignAdapterRegistry.isRegistered(id));
        }
        assertFalse(ESignAdapterRegistry.isRegistered("local_pki"));
        assertFalse(ESignAdapterRegistry.isRegistered(null));
    }

    @Test
    public void unknownExplicitProviderIsRejectedWithItsId() {
        try {
            ESignAdapterRegistry.resolveForInitiate("nonexistent", null);
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("nonexistent"));
            return;
        }
        throw new AssertionError("Expected an IllegalArgumentException");
    }

    @Test
    public void knownButUnconfiguredProviderNamesTheEnvVarsToSet() {
        // No ESIGN_EMUDHRA_* env in the test environment.
        try {
            ESignAdapterRegistry.resolve("emudhra");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("ESIGN_EMUDHRA_URL"));
            assertTrue(e.getMessage(), e.getMessage().contains("ESIGN_EMUDHRA_ASP_ID"));
            assertTrue(e.getMessage(), e.getMessage().contains("ESIGN_EMUDHRA_TRUST_CERTS"));
            assertTrue(e.getMessage(), e.getMessage().contains("ESIGN_EMUDHRA_ESP_CERT"));
            return;
        }
        throw new AssertionError("Expected an IllegalArgumentException");
    }

    @Test
    public void nonEsignAppDefaultIsSkippedInFavourOfDeploymentDefault() {
        // "local_pki" is a valid App default for sealing but not an eSign provider - must not fail lookup itself.
        assertEquals(ESignAdapterRegistry.SANDBOX, ESignAdapterRegistry.deploymentDefaultProviderId());
    }
}
