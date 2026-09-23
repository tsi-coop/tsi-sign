package org.tsicoop.sign.esign;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A set of certificates loaded from PEM file(s), used two ways: as trust anchors a signer
 * certificate must chain to ({@link #validates}), and as pinned certificates ({@link #isPinned}).
 * Revocation checking is not performed here (signer certs are ~30 minute, single-use).
 */
public final class TrustAnchors {

    private final Set<TrustAnchor> anchors = new HashSet<>();

    public static TrustAnchors load(List<Path> pemFiles) throws Exception {
        TrustAnchors trust = new TrustAnchors();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (Path file : pemFiles) {
            byte[] bytes = Files.readAllBytes(file);
            for (java.security.cert.Certificate cert : factory.generateCertificates(new ByteArrayInputStream(bytes))) {
                trust.anchors.add(new TrustAnchor((X509Certificate) cert, null));
            }
        }
        if (trust.anchors.isEmpty()) {
            throw new IllegalArgumentException("No certificates found in trust files " + pemFiles);
        }
        return trust;
    }

    /** True if {@code cert} is byte-for-byte one of the loaded certificates (certificate pinning). */
    public boolean isPinned(X509Certificate cert) {
        try {
            for (TrustAnchor anchor : anchors) {
                if (java.util.Arrays.equals(anchor.getTrustedCert().getEncoded(), cert.getEncoded())) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /** True if {@code leaf} chains (via {@code intermediates}) to a trusted anchor and is valid now. */
    public boolean validates(X509Certificate leaf, Collection<X509Certificate> intermediates) {
        try {
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(leaf);
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
            params.setRevocationEnabled(false);
            List<X509Certificate> pool = new ArrayList<>(intermediates);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool)));
            CertPathBuilder.getInstance("PKIX").build(params);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
