package org.cloudfoundry.identity.uaa.mfa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

public class MfaRegisterQRGenerator {

    private static final String OTPAUTH_TOTP_URI = "otpauth://totp/%s:%s?secret=%s&issuer=%s";

    private static final String STRING_ENCODING = "UTF-8";

    public static String getQRCode(String issuer,
                                   String accountName,
                                   String secretKey) throws WriterException, IOException {
        if(!StringUtils.hasText(issuer) || issuer.contains(":")) {
            throw new IllegalArgumentException("invalid issuer");
        }
        if(!StringUtils.hasText(accountName) || accountName.contains(":")) {
            throw new IllegalArgumentException("invalid account name");
        }

        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix qrBitMatrix = writer.encode(String.format(
                OTPAUTH_TOTP_URI,
                UriUtils.encode(issuer, STRING_ENCODING),
                UriUtils.encode(accountName, STRING_ENCODING),
                secretKey,
                UriUtils.encode(issuer, STRING_ENCODING)),
                BarcodeFormat.QR_CODE, 200, 200);
        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(qrBitMatrix);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ImageIO.write(qrImage, "png", os);
        return Base64.getEncoder().encodeToString(os.toByteArray());
    }

    public static String getQRCodePngDataUri(String issuer,
                                      String accountName,
                                      String secretKey) throws WriterException, IOException {
        return "data:image/png;base64," + getQRCode(issuer, accountName, secretKey);
    }
}
