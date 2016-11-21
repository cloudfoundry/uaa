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

package org.springframework.security.ldap.server;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.interceptor.Interceptor;
import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.referral.ReferralInterceptor;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.shared.ldap.exception.LdapNameNotFoundException;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.Lifecycle;
import org.springframework.core.io.Resource;
import sun.security.x509.X500Name;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.cloudfoundry.identity.uaa.util.SocketUtils.getSelfCertificate;

public class ApacheDsSSLContainer implements InitializingBean, DisposableBean, Lifecycle, ApplicationContextAware {
    private static final Log logger = LogFactory.getLog(ApacheDsSSLContainer.class);


    final DefaultDirectoryService service;
    LdapServer server;

    private ApplicationContext ctxt;
    private File workingDir;

    private boolean running;
    private final Resource[] ldifResources;
    private final JdbmPartition partition;
    private final String root;

    private int port = 53389;
    private int sslPort = 53636;

    private String keystoreFile;
    private boolean useStartTLS = false;

    public boolean isUseStartTLS() {
        return useStartTLS;
    }

    public ApacheDsSSLContainer setUseStartTLS(boolean useStartTLS) {
        this.useStartTLS = useStartTLS;
        return this;
    }

    public String getKeystoreFile() {
        return keystoreFile;
    }

    public ApacheDsSSLContainer setKeystoreFile(String keystoreFile) {
        this.keystoreFile = keystoreFile;
        return this;
    }

    public ApacheDsSSLContainer(String root, Resource[] ldifs) throws Exception {
        this.ldifResources = ldifs;
        service = new DefaultDirectoryService();
        List<Interceptor> list = new ArrayList<Interceptor>();

        //list.add(new NormalizationInterceptor());
        list.add(new AuthenticationInterceptor());
        list.add(new ReferralInterceptor());
        // list.add( new AciAuthorizationInterceptor() );
        // list.add( new DefaultAuthorizationInterceptor() );
        //list.add(new ExceptionInterceptor());
        // list.add( new ChangeLogInterceptor() );
        //list.add(new OperationalAttributeInterceptor());
        // list.add( new SchemaInterceptor() );
        //list.add(new SubentryInterceptor());
        // list.add( new CollectiveAttributeInterceptor() );
        // list.add( new EventInterceptor() );
        // list.add( new TriggerInterceptor() );
        // list.add( new JournalInterceptor() );

        //service.setInterceptors(list);
        partition = new JdbmPartition();
        partition.setId("rootPartition");
        partition.setSuffix(root);
        this.root = root;
        service.addPartition(partition);
        service.setExitVmOnShutdown(false);
        service.setShutdownHookEnabled(false);
        service.getChangeLog().setEnabled(false);
        service.setDenormalizeOpAttrsEnabled(true);
    }

    public ApacheDsSSLContainer setWorkingDirectory(File workingDir) {
        this.workingDir = workingDir;
        if (!workingDir.mkdirs()) {
            throw new RuntimeException("Unable to create directory:" + workingDir);
        }
        service.setWorkingDirectory(workingDir);
        return this;
    }

    public File getWorkingDirectory() {
        return workingDir;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        afterPropertiesSet(getKeystore(getWorkingDirectory()));
    }

    public ApacheDsSSLContainer afterPropertiesSet(File keystore) throws Exception {
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
        server.setKeystoreFile(keystore.getAbsolutePath());
        server.addExtendedOperationHandler(new StartTlsHandler());
        start();
        return this;
    }

    public ApacheDsSSLContainer setSslPort(int sslPort) {
        this.sslPort = sslPort;
        return this;
    }

    public ApacheDsSSLContainer setPort(int port) {
        this.port = port;
        return this;
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
        X509Certificate[] chain = {getSelfCertificate(new X500Name(commonName, organizationalUnit, organization, city, state, country), new Date(), (long) validity * 24 * 60 * 60, keyPair, "SHA256withRSA")};
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPass, chain);

        String keystoreName = "ldap.keystore";
        File keystore = new File(directory, keystoreName);
        if (!keystore.createNewFile()) {
            throw new FileNotFoundException("Unable to create file:" + keystore);
        }
        keyStore.store(new FileOutputStream(keystore, false), keyPass);
        return keystore;
    }



    @Override
    public void start() {
        if (isRunning()) {
            return;
        }

        if (service.isStarted()) {
            throw new IllegalStateException("DirectoryService is already running.");
        }

        logger.info("Starting directory server...");
        try {
            service.startup();
            server.start();
        } catch (Exception e) {
            throw new RuntimeException("Server startup failed", e);
        }

        try {
            service.getAdminSession().lookup(partition.getSuffixDn());
        } catch (LdapNameNotFoundException e) {
            try {
//                LdapDN dn = new LdapDN(root);
//                Assert.isTrue(root.startsWith("dc="));
//                String dc = root.substring(3, root.indexOf(','));
//                ServerEntry entry = service.newEntry(dn);
//                entry.add("objectClass", "top", "domain", "extensibleObject");
//                entry.add("dc", dc);
//                service.getAdminSession().add(entry);
                addPartition("testPartition", root);
            } catch (Exception e1) {
                logger.error("Failed to create dc entry", e1);
            }
        } catch (Exception e) {
            logger.error("Lookup failed", e);
        }

        running = true;

        try {
            importLdifs();
        } catch (Exception e) {
            throw new RuntimeException("Failed to import LDIF file(s)", e);
        }
    }

    protected Partition addPartition(String partitionId, String partitionDn)
        throws Exception {
        Partition partition = new JdbmPartition();
        partition.setId(partitionId);
        partition.setSuffix(partitionDn);
        service.addPartition(partition);
        return partition;
    }

    public void stop() {
        if (!isRunning()) {
            return;
        }

        logger.info("Shutting down directory server ...");
        try {
            server.stop();
            service.shutdown();
        } catch (Exception e) {
            logger.error("Shutdown failed", e);
            return;
        }

        running = false;

        if (workingDir.exists()) {
            logger.info("Deleting working directory " + workingDir.getAbsolutePath());
            deleteDir(workingDir);
        }
    }

    protected void importLdifs() throws Exception {
        // Import any ldif files
        Resource[] ldifs = ldifResources;

        // Note that we can't just import using the ServerContext returned
        // from starting Apache DS, apparently because of the long-running issue
        // DIRSERVER-169.
        // We need a standard context.
        // DirContext dirContext = contextSource.getReadWriteContext();

        if (ldifs == null || ldifs.length == 0) {
            return;
        }
        for (Resource resource : ldifs) {
            String ldifFile;
            try {
                ldifFile = resource.getFile().getAbsolutePath();
            } catch (IOException e) {
                ldifFile = resource.getURI().toString();
            }
            logger.info("Loading LDIF file: " + ldifFile);
            new LdifFileLoader(
                service.getAdminSession(),
                new File(ldifFile),
                null,
                getClass().getClassLoader()
            ).execute();
        }
    }

    protected String createTempDirectory(String prefix) throws IOException {
        String parentTempDir = System.getProperty("java.io.tmpdir");
        String fileNamePrefix = prefix + System.nanoTime();
        String fileName = fileNamePrefix;

        for (int i = 0; i < 1000; i++) {
            File tempDir = new File(parentTempDir, fileName);
            if (!tempDir.exists()) {
                return tempDir.getAbsolutePath();
            }
            fileName = fileNamePrefix + "~" + i;
        }

        throw new IOException("Failed to create a temporary directory for file at "
                                  + new File(parentTempDir, fileNamePrefix));
    }

    protected boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (String child : children) {
                boolean success = deleteDir(new File(dir, child));
                if (!success) {
                    return false;
                }
            }
        }

        return dir.delete();
    }

    public boolean isRunning() {
        return running;
    }

    public void destroy() throws Exception {
        stop();
    }

    public void setApplicationContext(ApplicationContext applicationContext)
        throws BeansException {
        ctxt = applicationContext;
    }

}

