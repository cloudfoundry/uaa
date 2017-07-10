package org.cloudfoundry.identity.uaa.impl;

import java.io.IOException;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonLocation;

public class JsonDateDeserializerTest {

	String testDateString = "2017-07-07T23:25:01.297Z";
	Exception exceptionOccured = null;

	@Test
	public void testParsing() throws IOException {
		Date d = JsonDateDeserializer.getDate(testDateString, new JsonLocation(null, 22, 0, 0));
		Assert.assertEquals(1499462701297L, d.getTime());
	}

	@Test
	public void testParsingParallel() throws IOException, InterruptedException {
		Thread[] threadArray = new Thread[1000];
		for (int i = 0; i < 1000; i++) {

			threadArray[i] = new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						Date d = JsonDateDeserializer.getDate(testDateString, new JsonLocation(null, 22, 0, 0));
						if(1499462701297L!= d.getTime())
						{
							throw new Exception("Unexpected date");
						}
					} catch (Exception e) {
						exceptionOccured = e;
					}
				}
			});
		}
		for (int i = 0; i < 1000; i++) {
			threadArray[i].start();
		}
		for (int i = 0; i < 1000; i++) {
			threadArray[i].join();
		}
		Assert.assertNull(exceptionOccured);
	}

}
