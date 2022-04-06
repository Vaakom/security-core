package ore.seccore.securitycore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CryptoTests {

    private String text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut" +
            " labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut " +
            "aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum " +
            "dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia " +
            "deserunt mollit anim id est laborum";

    public CryptoTests() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private SecretKeySpec generateKey() {
        byte[] keyBytes = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        String algorithm = "RawBytesa";

        return new SecretKeySpec(keyBytes, algorithm);
    }

    private IvParameterSpec generateIv() {
        byte[] keyBytes = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        return new IvParameterSpec(keyBytes);
    }

    @Test
    public void cypherAES() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        SecretKeySpec key = generateKey();
        IvParameterSpec iv = generateIv();

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        String decryptedText = new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);

        assertEquals(text, decryptedText);
    }
}
