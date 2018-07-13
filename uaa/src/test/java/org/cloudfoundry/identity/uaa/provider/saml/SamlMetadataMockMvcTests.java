/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import static org.hamcrest.Matchers.equalTo;
import static org.hibernate.validator.internal.util.Contracts.assertTrue;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class SamlMetadataMockMvcTests extends InjectedMockContextTest {

    @Test
    @Ignore("Used to generate data for comparison. XML comparison needs to ignore some elements")
    public void validate_SP_metadata() throws Exception {
        String file = "samlv1/saml-sp.xml";
        validateXmlMetadata(file, "/uaa/saml/metadata");
    }

    @Test
    @Ignore("Used to generate data for comparison. XML comparison needs to ignore some elements")
    public void validate_IDP_metadata() throws Exception {
        String file = "samlv1/saml-idp-formatted.xml";
        validateXmlMetadata(file, "/uaa/saml/idp/metadata");
    }

    protected void validateXmlMetadata(String file, String path) throws Exception {
        String expected = new String(getFileBytes(file), StandardCharsets.UTF_8);
        String actual = getMockMvc().perform(
            get(path)
                .contextPath("/uaa")
                .header("Host","localhost:8080")
                .accept(MediaType.TEXT_XML)
        )
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        meldCommand(format(expected), format(actual));
        assertThat(format(actual), equalTo(format(expected)));
    }

    protected void meldCommand(String expected, String actual) throws Exception {
        String expectedName = "/tmp/metadata-expected.xml";
        String actualName = "/tmp/metadata-actual.xml";
        File ex = new File(expectedName);
        File ac = new File(actualName);
        for (Tuple<String, File> file : Arrays.asList(
                new Tuple<>(expected, ex),
                new Tuple<>(actual, ac))
            ) {

            FileWriter fileWriter = new FileWriter(file.getY(), false);
            fileWriter.write(file.getX());
            fileWriter.flush();
        }
        System.err.println("meld command:\n\tmeld "+expectedName+" "+actualName);
    }

    protected byte[] getFileBytes(String path) throws IOException {
        ClassPathResource resource = new ClassPathResource(path);
        assertTrue(resource.exists(), path + " must exist.");
        return StreamUtils.copyToByteArray(resource.getInputStream());
    }

    public static String format(String xml) throws IOException, SAXException, ParserConfigurationException {

        xml = xml.replace("\n","").replace("\r","");

        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xml)));

        OutputFormat format = new OutputFormat(doc);
        format.setOmitComments(true);
        format.setIndenting(true);
        format.setIndent(2);
        format.setOmitXMLDeclaration(true);
        format.setLineWidth(Integer.MAX_VALUE);
        Writer outxml = new StringWriter();
        XMLSerializer serializer = new XMLSerializer(outxml, format);
        serializer.serialize(doc);
        return outxml.toString();
    }

    private static class Tuple<X,Y> {
        private final X x;
        private final Y y;

        private Tuple(X x, Y y) {
            this.x = x;
            this.y = y;
        }

        public X getX() {
            return x;
        }

        public Y getY() {
            return y;
        }
    }
}
