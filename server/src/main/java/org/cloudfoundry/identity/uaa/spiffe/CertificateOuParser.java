package org.cloudfoundry.identity.uaa.spiffe;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/** Extracts CF org/space/app GUIDs from the OU attributes of an instance cert subject. */
@Component
@ConditionalOnProperty(prefix = "uaa.spiffe", name = "instance-identity-ca")
public class CertificateOuParser {

    private static final String ORG_PREFIX = "organization:";
    private static final String SPACE_PREFIX = "space:";
    private static final String APP_PREFIX = "app:";

    public CfInstanceIdentity parse(X509Certificate certificate) {
        String org = null;
        String space = null;
        String app = null;

        X500Name subject;
        try {
            subject = new JcaX509CertificateHolder(certificate).getSubject();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("Unable to read certificate subject", e);
        }

        for (RDN rdn : subject.getRDNs()) {
            for (AttributeTypeAndValue typeAndValue : rdn.getTypesAndValues()) {
                if (!BCStyle.OU.equals(typeAndValue.getType())) {
                    continue;
                }
                String ou = IETFUtils.valueToString(typeAndValue.getValue());
                if (ou.startsWith(ORG_PREFIX)) {
                    org = ou.substring(ORG_PREFIX.length());
                } else if (ou.startsWith(SPACE_PREFIX)) {
                    space = ou.substring(SPACE_PREFIX.length());
                } else if (ou.startsWith(APP_PREFIX)) {
                    app = ou.substring(APP_PREFIX.length());
                }
            }
        }

        require(org, "organization");
        require(space, "space");
        require(app, "app");
        return new CfInstanceIdentity(org, space, app);
    }

    private static void require(String value, String name) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("Certificate is missing the '" + name + "' OU attribute");
        }
    }
}
