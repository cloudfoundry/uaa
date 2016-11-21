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
package org.cloudfoundry.identity.uaa.login;

import org.springframework.util.StringUtils;

import java.beans.PropertyEditorSupport;

/**
 * @author Dave Syer
 *
 */
public class PromptEditor extends PropertyEditorSupport {

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        if (StringUtils.hasText(text)) {
            setValue(Prompt.valueOf(text));
        }
        else {
            setValue(null);
        }
    }

    @Override
    public String getAsText() {
        Prompt value = (Prompt) getValue();
        return (value != null ? value.toString() : "");
    }

}
