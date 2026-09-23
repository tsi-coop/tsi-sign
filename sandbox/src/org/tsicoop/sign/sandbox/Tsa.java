package org.tsicoop.sign.sandbox;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;

/** Minimal RFC 3161 time-stamp authority backed by the sandbox CA's TSA certificate. */
final class Tsa {

    private static final SecureRandom RANDOM = new SecureRandom();

    static byte[] respond(MockCa ca, byte[] requestBytes) throws Exception {
        TimeStampRequest request = new TimeStampRequest(requestBytes);
        TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withRSA", ca.tsaKey, ca.tsaCert),
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier("1.2.3.4.5"));
        tokenGenerator.addCertificates(new JcaCertStore(List.of(ca.tsaCert, ca.rootCert)));
        TimeStampResponseGenerator generator = new TimeStampResponseGenerator(tokenGenerator, org.bouncycastle.tsp.TSPAlgorithms.ALLOWED);
        TimeStampResponse response = generator.generate(request, new BigInteger(64, RANDOM).add(BigInteger.ONE), new Date());
        return response.getEncoded();
    }

    private Tsa() {
    }
}
