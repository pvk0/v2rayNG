import java.io.File;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// Opens the release keystore the way the Android Gradle Plugin does, so a wrong
// secret fails here with a reason instead of "Failed to read key ...: null" at packaging.
public class KeyCheck {
    public static void main(String[] args) throws Exception {
        String file = args[0];
        char[] storePassword = System.getenv("KEYSTORE_PASSWORD").toCharArray();
        String alias = System.getenv("KEY_ALIAS");
        char[] keyPassword = System.getenv("KEY_PASSWORD").toCharArray();

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(new File(file), storePassword);
        } catch (Exception e) {
            fail("cannot open the keystore: APP_KEYSTORE_BASE64 is not a JKS/PKCS12 keystore or APP_KEYSTORE_PASSWORD is wrong");
            return;
        }

        if (!keyStore.isKeyEntry(alias)) {
            List<String> keys = new ArrayList<>();
            for (String name : Collections.list(keyStore.aliases())) {
                if (keyStore.isKeyEntry(name)) keys.add(name);
            }
            fail("APP_KEYSTORE_ALIAS is not a key in the keystore, its keys are: " + String.join(", ", keys));
        }

        try {
            keyStore.getKey(alias, keyPassword);
        } catch (Exception e) {
            String hint = keyStore.getType().equals("PKCS12") ? ", in a PKCS12 keystore it is normally the same as APP_KEYSTORE_PASSWORD" : "";
            fail("APP_KEY_PASSWORD does not unlock the key (" + e.getClass().getSimpleName() + ")" + hint);
        }
        System.out.println("Keystore OK: " + keyStore.getType());
    }

    private static void fail(String message) {
        System.out.println("::error::" + message);
        System.exit(1);
    }
}
