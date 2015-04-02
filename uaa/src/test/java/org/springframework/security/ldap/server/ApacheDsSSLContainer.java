package org.springframework.security.ldap.server;


import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

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
        CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
        X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, city, state, country);
        keypair.generate(keysize);
        PrivateKey privKey = keypair.getPrivateKey();
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = keypair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);
        keyStore.setKeyEntry(alias, privKey, keyPass, chain);
        String keystoreName = "ldap.keystore";
        File keystore = new File(directory, keystoreName);
        if (!keystore.createNewFile()) {
            throw new FileNotFoundException("Unable to create file:"+keystore);
        }
        keyStore.store(new FileOutputStream(keystore,false), keyPass);
        return keystore;
    }
}

