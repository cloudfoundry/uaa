package org.cloudfoundry.identity.web;

import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.is;

import org.junit.Assert;
import org.junit.Test;

public class PromptTest {

    @Test
    public void testPrompt() throws Exception {
        Prompt prompt = new Prompt("username", "text", "Username");
        Assert.assertThat(prompt.getName(), is("username"));
        Assert.assertThat(prompt.getDetails(), arrayContaining("text", "Username"));
    }
}