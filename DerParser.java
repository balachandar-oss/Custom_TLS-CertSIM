import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

public class DerParser {

    public static byte[] tbsCertificateBytes;
    public static byte[] signatureBytes;
    private static int rootChildIndex = 0;

    /**
     * Reads a TLV (Type-Length-Value) node from the buffer.
     */
    public static void parseNode(ByteBuffer buffer, int depth) {
        if (!buffer.hasRemaining()) return;

        int nodeStartPos = buffer.position();
        byte type = buffer.get();
        int length = readLength(buffer);

        if (depth == 0) rootChildIndex = 0; // Reset for new tree

        String indent = "  ".repeat(depth);

        // --- EXTRACTION LOGIC ---
        if (depth == 1) {
            if (rootChildIndex == 0 && type == 0x30) {
                int totalNodeLength = buffer.position() - nodeStartPos + length;
                tbsCertificateBytes = new byte[totalNodeLength];
                
                int savedPos = buffer.position();
                buffer.position(nodeStartPos);
                buffer.get(tbsCertificateBytes);
                buffer.position(savedPos);
                
                System.out.printf("%s[+] EXTRACTED: TBSCertificate (%d bytes)%n", indent, tbsCertificateBytes.length);
            } else if (rootChildIndex == 2 && type == 0x03) {
                buffer.get(); // skip unused bits
                signatureBytes = new byte[length - 1];
                buffer.get(signatureBytes);
                
                System.out.printf("%s[Type: %02X, Length: %d]%n", indent, type, length);
                System.out.printf("%s[+] EXTRACTED: ECDSA Signature Value (%d bytes)%n", indent, signatureBytes.length);
                
                rootChildIndex++;
                return;
            }
            rootChildIndex++;
        }

        System.out.printf("%s[Type: %02X, Length: %d]%n", indent, type, length);

        if (type == 0x30 || type == 0x31) {
            int endPos = buffer.position() + length;
            while (buffer.position() < endPos) {
                parseNode(buffer, depth + 1);
            }
        } else {
            byte[] valueBytes = new byte[length];
            buffer.get(valueBytes);
            
            if (type == 0x0C || type == 0x13 || type == 0x16) {
                String str = new String(valueBytes, java.nio.charset.StandardCharsets.UTF_8);
                System.out.printf("%s  => [String] %s%n", indent, str);
            } else if (type == 0x17 || type == 0x18) {
                String time = new String(valueBytes, java.nio.charset.StandardCharsets.US_ASCII);
                System.out.printf("%s  => [Time] %s%n", indent, time);
            } else if (type == 0x06) {
                String oid = parseOid(valueBytes);
                String name = mapOidToName(oid);
                if (name != null) {
                    System.out.printf("%s  => [OID] %s (%s)%n", indent, oid, name);
                } else {
                    System.out.printf("%s  => [OID] %s%n", indent, oid);
                }
            }
        }
    }

    private static int readLength(ByteBuffer buffer) {
        int length = buffer.get() & 0xFF;
        if (length <= 127) return length; 
        
        int numLengthBytes = length & 0x7F;
        int realLength = 0;
        for (int i = 0; i < numLengthBytes; i++) {
            realLength = (realLength << 8) | (buffer.get() & 0xFF);
        }
        return realLength;
    }

    public static boolean verifySignature(byte[] tbsCertificate, byte[] signature, String issuerPublicKeyHex) {
        try {
            System.out.println("\n[+] Initiating PKI Verification Engine...");

            byte[] pubKeyBytes = hexStringToByteArray(issuerPublicKeyHex);
            
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC"); 
            PublicKey rootPublicKey = kf.generatePublic(spec);
            
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(rootPublicKey);
            sig.update(tbsCertificate);
            
            boolean isValid = sig.verify(signature);
            
            if (isValid) {
                System.out.println("[+] VERIFIED: The Certificate is authentic and signed by the trusted Root CA!");
            } else {
                System.out.println("[-] REJECTED: Cryptographic signature mismatch. Possible Man-In-The-Middle!");
            }
            return isValid;
            
        } catch (Exception e) {
            System.err.println("[-] Signature Verification Failed: " + e.getMessage());
            return false;
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String parseOid(byte[] bytes) {
        if (bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        int first = bytes[0] & 0xFF;
        sb.append(first / 40).append(".").append(first % 40);
        int value = 0;
        for (int i = 1; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append(".").append(value);
                value = 0;
            }
        }
        return sb.toString();
    }

    private static String mapOidToName(String oid) {
        switch (oid) {
            case "2.5.4.3": return "Common Name (CN)";
            case "2.5.4.6": return "Country (C)";
            case "2.5.4.7": return "Locality (L)";
            case "2.5.4.8": return "State/Province (ST)";
            case "2.5.4.10": return "Organization (O)";
            case "2.5.4.11": return "Organizational Unit (OU)";
            case "1.2.840.10045.2.1": return "ecPublicKey";
            case "1.2.840.10045.4.3.2": return "ecdsa-with-SHA256";
            case "1.2.840.10045.3.1.7": return "prime256v1 (secp256r1)";
            default: return null;
        }
    }
}
