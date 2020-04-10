package org.cloudfoundry.identity.uaa.login;

import java.beans.PropertyEditorSupport;
import org.springframework.util.StringUtils;

/** @author Dave Syer */
public class PromptEditor extends PropertyEditorSupport {

  @Override
  public String getAsText() {
    Prompt value = (Prompt) getValue();
    return (value != null ? value.toString() : "");
  }

  @Override
  public void setAsText(String text) throws IllegalArgumentException {
    if (StringUtils.hasText(text)) {
      setValue(Prompt.valueOf(text));
    } else {
      setValue(null);
    }
  }
}
