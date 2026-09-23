package org.tsicoop.sign.sandbox;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * What an ESP does: it is handed only a document HASH, never the document, and returns a
 * detached PKCS#7/CMS signature whose signed messageDigest attribute is exactly that hash -
 * so it verifies against the original PDF's ByteRange content without the ESP ever seeing it.
 */
final class HashSigner {

    static byte[] signHash(byte[] documentHash, PrivateKey key, X509Certificate signerCert, X509Certificate... chain)
            throws Exception {
        CMSAttributeTableGenerator attributes = parameters -> {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));
            v.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(documentHash))));
            v.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))));
            return new AttributeTable(v);
        };
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(key);
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .setSignedAttributeGenerator(attributes)
                        .build(signer, new X509CertificateHolder(signerCert.getEncoded())));
        java.util.ArrayList<X509Certificate> certs = new java.util.ArrayList<>(List.of(signerCert));
        certs.addAll(List.of(chain));
        generator.addCertificates(new JcaCertStore(certs));
        // The content argument is ignored: the attribute generator above pins messageDigest to the supplied hash.
        return generator.generate(new CMSProcessableByteArray(documentHash), false).getEncoded();
    }

    private HashSigner() {
    }
}
