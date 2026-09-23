package org.tsicoop.sign.sandbox;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/** XML-DSig (enveloped, RSA-SHA256) as the CCA eSign API requires on both request and response. */
final class Dsig {

    static final String DSIG_NS = XMLSignature.XMLNS;

    static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    static String serialize(Document doc) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter out = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(out));
        return out.toString();
    }

    /** Appends an enveloped signature (whole-document reference) carrying the signer's certificate in KeyInfo. */
    static void sign(Document doc, PrivateKey key, X509Certificate cert) throws Exception {
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        Reference ref = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
        SignedInfo signedInfo = factory.newSignedInfo(
                factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), Collections.singletonList(ref));
        KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(cert));
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
        factory.newXMLSignature(signedInfo, keyInfo)
                .sign(new DOMSignContext(key, doc.getDocumentElement()));
    }

    /**
     * Verifies the document's single enveloped signature using the certificate embedded in its own KeyInfo.
     * Returns that certificate (whose trust the caller must decide), or null if the signature is missing/invalid.
     */
    static X509Certificate verifyAndGetSigner(Document doc) {
        try {
            NodeList signatures = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
            if (signatures.getLength() != 1) {
                return null;
            }
            Element signatureElement = (Element) signatures.item(0);
            // Only an enveloped signature that is a direct child of the root covers the whole document.
            if (signatureElement.getParentNode() != doc.getDocumentElement()) {
                return null;
            }
            EmbeddedCertSelector selector = new EmbeddedCertSelector();
            DOMValidateContext context = new DOMValidateContext(selector, signatureElement);
            XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
            for (Object o : signature.getSignedInfo().getReferences()) {
                if (!"".equals(((Reference) o).getURI())) {
                    return null;
                }
            }
            return signature.validate(context) ? selector.certificate : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static final class EmbeddedCertSelector extends KeySelector {
        X509Certificate certificate;

        @Override
        public KeySelectorResult select(javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo, Purpose purpose,
                AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            if (keyInfo != null) {
                for (Object info : keyInfo.getContent()) {
                    if (info instanceof X509Data) {
                        for (Object item : ((X509Data) info).getContent()) {
                            if (item instanceof X509Certificate) {
                                certificate = (X509Certificate) item;
                                Key key = certificate.getPublicKey();
                                return () -> key;
                            }
                        }
                    }
                }
            }
            throw new KeySelectorException("No X509Certificate in KeyInfo");
        }
    }

    private Dsig() {
    }
}
