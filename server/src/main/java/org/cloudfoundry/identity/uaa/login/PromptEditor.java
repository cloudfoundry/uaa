
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
