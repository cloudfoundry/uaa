/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.util;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.io.File;

public class ApacheDSHelper {
    public static ApacheDsSSLContainer start() throws Exception {
        return start(33389, 33636);
    }
    public static ApacheDsSSLContainer start(int port, int sslPort) throws Exception {
        ApacheDsSSLContainer apacheDS;
        File tmpDir;

        tmpDir = new File(System.getProperty("java.io.tmpdir")+"/apacheds/"+new RandomValueStringGenerator().generate());
        tmpDir.deleteOnExit();
        System.out.println(tmpDir);
        //configure properties for running against ApacheDS
        apacheDS = new ApacheDsSSLContainer("dc=test,dc=com",new Resource[] {new ClassPathResource("ldap_init_apacheds.ldif"), new ClassPathResource("ldap_init.ldif")});
        apacheDS.setWorkingDirectory(tmpDir);
        apacheDS.setPort(port);
        apacheDS.setSslPort(sslPort);
        apacheDS.afterPropertiesSet();

        return apacheDS;
    }
}
