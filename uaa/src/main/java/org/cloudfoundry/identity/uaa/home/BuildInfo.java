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
package org.cloudfoundry.identity.uaa.home;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.util.Assert;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

public class BuildInfo implements InitializingBean {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${uaa.url:http://localhost:8080/uaa}")
    private String uaaUrl;
    private String version;
    private String commitId;
    private String timestamp;

    @Override
    public void afterPropertiesSet() {
        try {
            Properties gitProperties = PropertiesLoaderUtils.loadAllProperties("git.properties");
            commitId = gitProperties.getProperty("git.commit.id.abbrev", "UNKNOWN");
            String currentTime = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date());
            timestamp = gitProperties.getProperty("git.commit.time", currentTime);
        } catch (IOException e) {
            logger.debug("Exception loading git.properties", e);
        }
        try {
            Properties buildProperties = PropertiesLoaderUtils.loadAllProperties("build.properties");
            version = buildProperties.getProperty("build.version");
        } catch (IOException e) {
            logger.debug("Exception loading build.properties", e);
        }
        Assert.hasText(uaaUrl);
        Assert.hasText(version);
        Assert.hasText(commitId);
        Assert.hasText(timestamp);
    }

    public String getVersion() {
        return version;
    }

    public String getCommitId() {
        return commitId;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getUaaUrl() {
        return uaaUrl;
    }
}
