package ore.seccore.securitycore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;

public class KeystoreTests {

    public KeystoreTests() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void keystore() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

    }
}
