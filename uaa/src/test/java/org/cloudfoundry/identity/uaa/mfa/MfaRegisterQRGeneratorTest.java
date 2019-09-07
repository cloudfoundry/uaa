package org.cloudfoundry.identity.uaa.mfa;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.DecodeHintType;
import com.google.zxing.FormatException;
import com.google.zxing.NotFoundException;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.junit.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MfaRegisterQRGeneratorTest {

    @Test
    public void testQRCode() throws Exception {
        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        String encodedQrCode = MfaRegisterQRGenerator.getQRCode("testIssuer", "accountName", key.getKey());
        String result = decodeQrPng(encodedQrCode);

        String[] split = result.split("\\?");
        assertEquals("otpauth://totp/testIssuer:accountName", split[0]);
        List<String> list = Arrays.asList(split[1].split("&"));
        assertTrue(list.contains("issuer=testIssuer"));
        assertTrue(list.contains("secret=" + key.getKey()));
        assertEquals(2, list.size());
    }

    @Test
    public void testQrWithSpecialChars() throws Exception {
        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        String encodedQrCode = MfaRegisterQRGenerator.getQRCode("test=Issuer","account?&#Name", key.getKey());
        String result = decodeQrPng(encodedQrCode);

        String[] split = result.split("\\?");
        assertEquals("otpauth://totp/test%3DIssuer:account%3F%26%23Name", split[0]);
        List<String> list = Arrays.asList(split[1].split("&"));
        assertTrue(list.contains("issuer=test%3DIssuer"));
        assertTrue(list.contains("secret=" + key.getKey()));
        assertEquals(2, list.size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testQrWithColonIssuer() throws Exception {
        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        String encodedQrCode = MfaRegisterQRGenerator.getQRCode("test:Issuer", "accountName", key.getKey());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testQrWithColonAccountName() throws Exception {
        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        String encodedQrCode = MfaRegisterQRGenerator.getQRCode("testIssuer", "accountName:", key.getKey());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEmptyIssuer() throws Exception {
        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        String encodedQrCode = MfaRegisterQRGenerator.getQRCode("", "accountName", key.getKey());
    }

    @Test
    public void testPngUrl() throws Exception {
        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        String encodedQrCode = MfaRegisterQRGenerator.getQRCodePngDataUri("testIssuer", "accountName", key.getKey());
        assertTrue(encodedQrCode.startsWith("data:image/png;base64,"));
        String rawSplit = encodedQrCode.split(",")[1];
        String[] split = decodeQrPng(rawSplit).split("\\?");

        assertEquals("otpauth://totp/testIssuer:accountName", split[0]);
        List<String> list = Arrays.asList(split[1].split("&"));
        assertTrue("url did not contain issuer", list.contains("issuer=testIssuer"));
        assertTrue("url did not contain secret", list.contains("secret=" + key.getKey()));
        assertEquals(2, list.size());
    }

    private String decodeQrPng(String encodedQrCode) throws IOException, NotFoundException, ChecksumException, FormatException {
        byte[] decodedByte = Base64.getDecoder().decode(encodedQrCode);

        BufferedImage image = ImageIO.read(new ByteArrayInputStream(decodedByte));
        BufferedImageLuminanceSource source = new BufferedImageLuminanceSource(image);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        QRCodeReader reader = new QRCodeReader();
        Map<DecodeHintType, Object> hintMap = new HashMap<>();
        hintMap.put(DecodeHintType.PURE_BARCODE, true);
        return reader.decode(bitmap, hintMap).getText();
    }

}