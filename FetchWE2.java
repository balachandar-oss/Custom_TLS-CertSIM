import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class FetchWE2 {
    public static void main(String[] args) throws Exception {
        URL url = new URL("https://google.com");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.connect();
        
        for (Certificate cert : conn.getServerCertificates()) {
            if (cert instanceof X509Certificate) {
                X509Certificate x509 = (X509Certificate) cert;
                String subject = x509.getSubjectX500Principal().getName();
                
                if (subject.contains("WE2")) {
                    byte[] spki = x509.getPublicKey().getEncoded();
                    StringBuilder sb = new StringBuilder();
                    for (byte b : spki) {
                        sb.append(String.format("%02X", b));
                    }
                    System.out.println(sb.toString());
                    return;
                }
            }
        }
    }
}
