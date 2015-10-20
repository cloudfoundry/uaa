package org.springframework.security.ldap.server;


import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

public class ApacheDsSSLContainer extends ApacheDSContainer {
    private int port = 53389;
    private int sslPort = 53636;

    private String keystoreFile;
    private File workingDir;
    private boolean useStartTLS = false;

    public boolean isUseStartTLS() {
        return useStartTLS;
    }

    public void setUseStartTLS(boolean useStartTLS) {
        this.useStartTLS = useStartTLS;
    }

    public String getKeystoreFile() {
        return keystoreFile;
    }

    public void setKeystoreFile(String keystoreFile) {
        this.keystoreFile = keystoreFile;
    }

    public ApacheDsSSLContainer(String root, String ldifs) throws Exception {
        super(root, ldifs);
    }

    @Override
    public void setWorkingDirectory(File workingDir) {
        super.setWorkingDirectory(workingDir);
        this.workingDir = workingDir;
        if (!workingDir.mkdirs()) {
            throw new RuntimeException("Unable to create directory:"+workingDir);
        }
    }

    public File getWorkingDirectory() {
        return workingDir;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        server = new LdapServer();
        server.setDirectoryService(service);
        TcpTransport sslTransport = new TcpTransport(sslPort);
        if (isUseStartTLS()) {
            server.addExtendedOperationHandler(new StartTlsHandler());
        } else {
            sslTransport.setEnableSSL(true);
        }
        TcpTransport tcpTransport = new TcpTransport(port);
        server.setTransports(sslTransport, tcpTransport);
        assert server.isEnableLdaps(sslTransport);
        assert !server.isEnableLdaps(tcpTransport);
        server.setCertificatePassword("password");
        server.setKeystoreFile(getKeystore(getWorkingDirectory()).getAbsolutePath());
        start();
    }

    public void setSslPort(int sslPort) {
        this.sslPort = sslPort;
    }

    @Override
    public void setPort(int port) {
        super.setPort(port);
        this.port = port;
    }


    private static final int keysize = 1024;
    private static final String commonName = "localhost";
    private static final String organizationalUnit = "UAA";
    private static final String organization = "Pivotal Software";
    private static final String city = "San Francisco";
    private static final String state = "CA";
    private static final String country = "UA";
    private static final long validity = 1096; // 3 years
    private static final String alias = "uaa-ldap";
    private static final char[] keyPass = "password".toCharArray();

    //mimic what the keytool does
    public File getKeystore(File directory) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate[] chain = {getSelfCertificate(new X500Name(commonName, organizationalUnit, organization, city, state, country), new Date(), (long) validity * 24 * 60 * 60, keyPair, "SHA1WithRSA")};
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPass, chain);

        String keystoreName = "ldap.keystore";
        File keystore = new File(directory, keystoreName);
        if (!keystore.createNewFile()) {
            throw new FileNotFoundException("Unable to create file:"+keystore);
        }
        keyStore.store(new FileOutputStream(keystore,false), keyPass);
        return keystore;
    }

    private static X509Certificate getSelfCertificate(X500Name x500Name, Date issueDate, long validForSeconds, KeyPair keyPair, String signatureAlgorithm) throws CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

        try {
            Date expirationDate = new Date();
            expirationDate.setTime(issueDate.getTime() + validForSeconds * 1000L);

            X509CertInfo certInfo = new X509CertInfo();
            certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber((new Random()).nextInt() & Integer.MAX_VALUE));
            certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(signatureAlgorithm)));

            certInfo.set(X509CertInfo.SUBJECT, x500Name);
            certInfo.set(X509CertInfo.ISSUER, x500Name);

            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
            certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(issueDate, expirationDate));

            X509CertImpl selfSignedCert = new X509CertImpl(certInfo);
            selfSignedCert.sign(keyPair.getPrivate(), signatureAlgorithm);
            return selfSignedCert;
        } catch (IOException ioe) {
            throw new CertificateEncodingException("Error during creation of self-signed Certificate: " + ioe.getMessage());
        }
    }

}

