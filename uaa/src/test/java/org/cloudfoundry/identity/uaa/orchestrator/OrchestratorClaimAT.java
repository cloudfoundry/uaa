/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ge.predix.iam.kubernetes.enums.ServiceName;
import com.ge.predix.iam.kubernetes.exception.ServiceInstanceProviderException;
import com.ge.predix.iam.kubernetes.model.Claim;
import com.ge.predix.iam.kubernetes.utils.AssumeRoleUtil;
import com.ge.predix.iam.kubernetes.utils.OrchestratorUtil;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = OrchestratorIntegrationTestConfig.class)
public class OrchestratorClaimAT {

    @Value("${kubernetes.config.secondary-namespace}")
    private String namespace;

    @Autowired
    private OrchestratorUtil orchestratorUtil;

    @Autowired
    private AssumeRoleUtil assumeRoleUtil;

    private static final Logger LOGGER = LoggerFactory.getLogger(OrchestratorClaimAT.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeClass
    public static void setupClassLevelData() {
        LOGGER.info("In OrchestratorClaimAT.setupClassLevelData()");
    }

    @Before
    public void setupTestLevelData() {
        LOGGER.info("In OrchestratorClaimAT.setupTestLevelData()");
    }

    @Test
    public void dummyTestTryAwsLogin() throws Exception {
        LOGGER.info("In OrchestratorClaimAT.dummyTestTryAwsLogin()");
        LOGGER.info("Print loaded env vars and autowired beans");
        LOGGER.info("AssumeRoleUtil: {}", assumeRoleUtil);
        LOGGER.info("OrchestratorUtil: {}", orchestratorUtil);
        LOGGER.info("Loaded env var kubernetes.config.secondary-namespace: {}", namespace);

        LOGGER.info("\nPerform gossamer aws login and assume role\n");
        LOGGER.info("\nK8S Api Client returned: {}", assumeRoleUtil.getKubernetesApiClient());
    }

    // This is dummy test added to validate OrchestratorUtil functionality, temporarily expecting
    // ServiceInstanceProviderException as UAA is not onboarded yet and can be removed later
    // once UAA is onboarded and when we add actual uaa orchestrator integration tests.
    @Test(expected = ServiceInstanceProviderException.class)
    public void testDummyUaaCreateZone() throws Exception {
        LOGGER.info("In OrchestratorClaimAT.testDummyUaaCreateZone()");

        String claimName = "test-uaa-claim";
        Claim claim = null;
        boolean isClaimCreated = false;
        try {
            isClaimCreated = createZone(claimName, null);
            claim = getZone(claimName);
            LOGGER.info("Fetched claim: {}", claim);
        } finally {
            if (isClaimCreated) {
                deleteZone(claimName);
            }
        }
    }

    private boolean createZone(final String claimName, final Object request)
        throws ServiceInstanceProviderException {
        try {
            orchestratorUtil.createService(claimName, ServiceName.UAA, OBJECT_MAPPER.valueToTree(request));
            return true;
        } catch (ServiceInstanceProviderException e) {
            LOGGER.error("UAA Claim create failed for claimName: {}, request:{}, errorMessage: {}",
                         claimName, request, e.getMessage(), e);
            throw e;
        }
    }

    private Claim getZone(final String claimName) throws ServiceInstanceProviderException {
        try {
            return orchestratorUtil.readClaim(claimName, ServiceName.UAA);
        } catch (ServiceInstanceProviderException e) {
            LOGGER.error("UAA Claim read failed for claimName: {}, errorMessage: {}", claimName,
                         e.getMessage(), e);
            throw e;
        }
    }

    private boolean deleteZone(final String claimName) throws ServiceInstanceProviderException {
        try {
            orchestratorUtil.deleteClaim(claimName, ServiceName.UAA);
            return true;
        } catch (ServiceInstanceProviderException e) {
            LOGGER.error("UAA Claim delete failed for claimName: {}, errorMessage: {}", claimName,
                         e.getMessage(), e);
            throw e;
        }
    }
}
