import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IClientCredential;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

public class CertificateFlow {

    private static final String PRIVATE_KEY_FILE = "<path to>/privateKey.pem";
    private static final String PUBLIC_KEY_FILE = "<path to>certificate.pem";
    private static final String USER_CLIENT_ID = "client id provided by seatank";
    private static final String SEATANK_TENANT_ID = "2381cf1b-4fa9-428a-946f-b2483f3c289e";
    private static final String SEATANK_API_SCOPE = "api://api.seatankterminal.com/.default";

    public static void main(String args[]) throws Exception {

        // Load the private key and public key
        PrivateKey privateKey = loadEncryptedPrivateKey(PRIVATE_KEY_FILE, "<passphrase here>");
        X509Certificate publicKey = loadCertificate(PUBLIC_KEY_FILE);
        IClientCredential credential = ClientCredentialFactory.createFromCertificate(privateKey, publicKey);

        // See https://learn.microsoft.com/en-us/entra/msal/java/getting-started/client-credentials#client-credentials-with-certificate
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(USER_CLIENT_ID, credential).build();
        app.acquireToken(ClientCredentialParameters
                        .builder(Collections.singleton(SEATANK_API_SCOPE))
                        .tenant(SEATANK_TENANT_ID)
                        .build())
                .thenAccept(result -> System.out.println("Access token: " + result.accessToken()))
                .join();
    }

    public static PrivateKey loadEncryptedPrivateKey(String filepath, String passphrase) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        File privateKeyFile = new File(filepath); // private key file in PEM format
        var pemParser = new PEMParser(new FileReader(privateKeyFile));
        var object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp;
        if (object instanceof PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) {
            var decryptorProviderBuilder = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");
            var privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProviderBuilder.build(passphrase.toCharArray()));
            return converter.getPrivateKey(privateKeyInfo);
        }
        return null;
    }

    public static X509Certificate loadCertificate(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(fis);
        }
    }
}
