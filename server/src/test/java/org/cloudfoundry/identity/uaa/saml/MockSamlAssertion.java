/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.saml;


import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.opensaml.saml2.core.Assertion;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.PathResource;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileWriter;
import java.util.Map;

public class MockSamlAssertion {

    public static final String RAW_YAML = "raw-yaml";

    public Map<String, Object> getYamlConfig(Resource resource) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        factory.setResources(new Resource[] {resource});
        Map<String, Object> result = factory.getObject();
        String yamlStr = (new Yaml()).dump(result);
        result.put(RAW_YAML, yamlStr);
        return result;
    }

    public Object getProperty(String p, Map<String,Object> config) {
        int dot = p.indexOf(".");
        if (dot >=0) {
            String property = p.substring(0, dot);
            String remaining = p.substring(dot+1);
            Map<String, Object> sub = (Map<String, Object>) config.get(property);
            return getProperty(remaining, sub);
        } else {
            return config.get(p);
        }
    }

    public static void main(String[] args) throws Exception {
        MockSamlAssertion mock = new MockSamlAssertion();
        Resource resource = new ClassPathResource("saml/mock-assertion-local-testzone4.yml");
        if (args!=null && args.length>0) {
            PathResource pathResource = new PathResource(args[0]);
            if (!(pathResource.exists() && pathResource.isReadable())) {
                String message = "Unable to load resource[path:" + args[0] + "; readable:" + pathResource.isReadable() + "; exists:" + pathResource.exists() + "]";
                System.err.println("\n\n\n=======================ASSERTION ERROR=====================\n");
                System.err.println(message);
                System.err.println("\n========================ASSERTION ERROR======================\n\n\n");
                throw new Exception(message);
            }
            resource = pathResource;
        }
        System.out.println("Processing assertion for config:"+resource.getURL());
        Map<String, Object> config = mock.getYamlConfig(resource);
        SamlTestUtils saml = new SamlTestUtils();
        saml.initialize();

        String audienceEntityId = (String) mock.getProperty("saml.audience.entity-id", config);
        String nameIdFormat = (String) mock.getProperty("saml.audience.nameid-format", config);
        String endpoint = (String) mock.getProperty("saml.audience.endpoint", config);

        String username = (String) mock.getProperty("saml.issuer.username", config);
        String issuerEntityId = (String) mock.getProperty("saml.issuer.entity-id", config);
        String privateKey = (String) mock.getProperty("saml.issuer.signing.key", config);
        String keyPassword = (String) mock.getProperty("saml.issuer.signing.passphrase", config);
        String certificate = (String) mock.getProperty("saml.issuer.signing.cert", config);

        Assertion assertion = saml.mockAssertion(issuerEntityId, nameIdFormat, username, endpoint, audienceEntityId, privateKey, keyPassword, certificate);
        System.out.println("\n\n\n=======================ASSERTION START=====================\n");
        String encoded = saml.mockAssertionEncoded(assertion);
        System.out.println(encoded);
        System.out.println("\n========================ASSERTION END======================\n\n\n");

        File assertionFile = new File(System.getProperty("java.io.tmpdir", "/tmp"), "assertion.txt");
        if (assertionFile.exists()) {
            assertionFile.delete();
        }
        FileWriter fileWriter = new FileWriter(assertionFile, false);
        fileWriter.write(encoded);
        fileWriter.flush();
        fileWriter.close();
        System.out.println("Assertion stored in:"+assertionFile.getAbsolutePath());
    }
}
