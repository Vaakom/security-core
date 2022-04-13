package ore.seccore.securitycore;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignatureTests {

    private String text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut" +
            " labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut " +
            "aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum " +
            "dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia " +
            "deserunt mollit anim id est laborum";

    private KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        return keyPairGenerator.generateKeyPair();
    }

    private byte[] createSign(PrivateKey key, String text) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithDSA");
        signature.initSign(key, new SecureRandom());

        signature.update(text.getBytes(StandardCharsets.UTF_8));

        return signature.sign();
    }

    private boolean verify(PublicKey key, String text, byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithDSA");
        signature.initVerify(key);
        signature.update(text.getBytes(StandardCharsets.UTF_8));

        return signature.verify(sign);
    }

    @Test
    public void signature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        KeyPair keyPair = getKeyPair();

        byte[] sign = createSign(keyPair.getPrivate(), text);

        assertTrue(verify(keyPair.getPublic(), text, sign));
    }
}
