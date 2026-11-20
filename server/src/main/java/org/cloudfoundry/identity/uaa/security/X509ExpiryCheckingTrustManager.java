/*
 *********************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.security;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Default-trust manager that also rejects expired certificates. Extends
 * {@link X509ExtendedTrustManager} so the delegate still performs endpoint identification.
 */
public class X509ExpiryCheckingTrustManager extends X509ExtendedTrustManager {

    private X509TrustManager delegate;

    public X509ExpiryCheckingTrustManager() {
        try {
            TrustManagerFactory tmf;
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            X509TrustManager x509Tm = null;
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager manager) {
                    x509Tm = manager;
                    break;
                }
            }
            delegate = x509Tm;
        } catch (NoSuchAlgorithmException | KeyStoreException _) {
            // ignore
        }
    }

    protected void setDelegate(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        requireDelegate().checkClientTrusted(x509Certificates, s);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkClientTrusted(x509Certificates, s, socket);
        } else {
            tm.checkClientTrusted(x509Certificates, s);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine engine) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkClientTrusted(x509Certificates, s, engine);
        } else {
            tm.checkClientTrusted(x509Certificates, s);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        requireDelegate().checkServerTrusted(x509Certificates, s);
        checkValidity(x509Certificates);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkServerTrusted(x509Certificates, s, socket);
        } else {
            verifyHostname(x509Certificates, socket instanceof SSLSocket ss ? ss.getSSLParameters() : null, peerHost(socket));
            tm.checkServerTrusted(x509Certificates, s);
        }
        checkValidity(x509Certificates);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine engine) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkServerTrusted(x509Certificates, s, engine);
        } else {
            verifyHostname(x509Certificates, engine == null ? null : engine.getSSLParameters(), peerHost(engine));
            tm.checkServerTrusted(x509Certificates, s);
        }
        checkValidity(x509Certificates);
    }

    // A non-extended delegate does not check hostnames (SunJSSE used to do it for plain X509TrustManagers),
    // so do it here when endpoint identification is requested.
    private static void verifyHostname(X509Certificate[] chain, SSLParameters params, String host) throws CertificateException {
        String algorithm = params == null ? null : params.getEndpointIdentificationAlgorithm();
        if (algorithm == null || algorithm.isEmpty()) {
            return;
        }
        if (!"HTTPS".equalsIgnoreCase(algorithm) && !"LDAPS".equalsIgnoreCase(algorithm)) {
            throw new CertificateException("Unsupported endpoint identification algorithm: " + algorithm);
        }
        if (host == null || chain == null || chain.length == 0) {
            throw new CertificateException("Unable to determine peer host for hostname verification");
        }
        String name = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        if (!matches(chain[0], name)) {
            throw new CertificateException("No subject alternative names matching host " + host);
        }
    }

    private static String peerHost(Socket socket) {
        if (socket instanceof SSLSocket ssl) {
            SSLSession session = ssl.getHandshakeSession();
            if (session != null && session.getPeerHost() != null) {
                return session.getPeerHost();
            }
        }
        return socket == null || socket.getInetAddress() == null ? null : socket.getInetAddress().getHostName();
    }

    private static String peerHost(SSLEngine engine) {
        if (engine == null) {
            return null;
        }
        SSLSession session = engine.getHandshakeSession();
        return session != null && session.getPeerHost() != null ? session.getPeerHost() : engine.getPeerHost();
    }

    private static boolean matches(X509Certificate cert, String host) throws CertificateException {
        boolean isIp = InetAddressUtils.isIpLiteral(host);
        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        boolean hasTypedSan = false;
        if (sans != null) {
            for (List<?> san : sans) {
                int type = (Integer) san.get(0);
                if (isIp && type == 7) {
                    hasTypedSan = true;
                    if (InetAddressUtils.sameIp(host, (String) san.get(1))) {
                        return true;
                    }
                } else if (!isIp && type == 2) {
                    hasTypedSan = true;
                    if (matchesDns((String) san.get(1), host)) {
                        return true;
                    }
                }
            }
        }
        if (hasTypedSan || isIp) {
            return false;
        }
        // No DNS SANs: fall back to the most specific common name
        try {
            String cn = null;
            for (Rdn rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    cn = rdn.getValue().toString();
                    break;
                }
            }
            return cn != null && matchesDns(cn, host);
        } catch (InvalidNameException e) {
            throw new CertificateException(e);
        }
    }

    private static boolean matchesDns(String pattern, String host) {
        String p = pattern.toLowerCase(Locale.ROOT);
        String h = host.toLowerCase(Locale.ROOT);
        if (p.endsWith(".")) {
            p = p.substring(0, p.length() - 1);
        }
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (p.startsWith("*.")) {
            int dot = h.indexOf('.');
            return dot > 0 && p.substring(1).equals(h.substring(dot)) && p.indexOf('.', 2) > 0;
        }
        return p.equals(h);
    }

    private static final class InetAddressUtils {
        static boolean isIpLiteral(String host) {
            return host.indexOf(':') >= 0 || host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
        }

        static boolean sameIp(String a, String b) {
            try {
                return InetAddress.getByName(a).equals(InetAddress.getByName(b));
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }
    private X509TrustManager requireDelegate() throws CertificateException {
        if (delegate == null) {
            throw new CertificateException();
        }
        return delegate;
    }

    private static void checkValidity(X509Certificate[] x509Certificates) throws CertificateException {
        for (X509Certificate certificate : x509Certificates) {
            certificate.checkValidity();
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        if (delegate != null) {
            return delegate.getAcceptedIssuers();
        }
        return new X509Certificate[0];
    }
}
