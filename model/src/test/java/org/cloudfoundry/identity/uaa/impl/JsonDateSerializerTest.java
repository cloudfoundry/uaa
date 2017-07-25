package org.cloudfoundry.identity.uaa.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

public class JsonDateSerializerTest {

	String testDateString = "2017-07-07T23:25:01.297Z";
	Exception exceptionOccured = null;

	@Test
	public void testFormatting() throws IOException, ParseException {
		Date now = new Date();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		JsonGenerator gen = new JsonFactory().createGenerator(bos);
		new JsonDateSerializer().serialize(now, gen, null);
		gen.close();
		Assert.assertEquals(String.format("\"%s\"", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(now)),
				bos.toString());
	}

	@Test
	public void testFormattingParallel() throws IOException, InterruptedException {
		Thread[] threadArray = new Thread[1000];
		for (int i = 0; i < 1000; i++) {

			threadArray[i] = new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						Date now = new Date();
						ByteArrayOutputStream bos = new ByteArrayOutputStream();
						JsonGenerator gen = new JsonFactory().createGenerator(bos);
						new JsonDateSerializer().serialize(now, gen, null);
						gen.close();
						if (!String.format("\"%s\"", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(now))
								.equals(bos.toString())) {
							throw new Exception("Unexpected date");
						}

					} catch (Exception e) {
						exceptionOccured = e;
					}
				}
			});
		}
		for (

				int i = 0; i < 1000; i++) {
			threadArray[i].start();
		}
		for (int i = 0; i < 1000; i++) {
			threadArray[i].join();
		}
		Assert.assertNull(exceptionOccured);
	}

}
