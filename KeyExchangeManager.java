import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;

public class KeyExchangeManager {

    private KeyPair clientKeyPair;

    public KeyExchangeManager() {
        try {
            // 1. Initialize EC KeyPairGenerator for secp256r1
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyGen.initialize(ecSpec);
            
            // 2. Generate Client's ephemeral Key Pair
            this.clientKeyPair = keyGen.generateKeyPair();
            System.out.println("[+] KeyExchangeManager: Client EC KeyPair (secp256r1) generated securely.");
        } catch (Exception e) {
            System.err.println("[-] KeyExchangeManager Init Error: " + e.getMessage());
        }
    }

    /**
     * Reconstructs the Server's EC Public Key from raw bytes and generates the Shared Secret.
     */
    public byte[] generateSharedSecret(byte[] serverPubKeyBytes) {
        try {
            // TLS 1.2 ECDHE ServerKeyExchange sends the raw EC point bytes
            // The first byte must be 0x04 (indicating uncompressed format)
            if (serverPubKeyBytes[0] != 0x04) {
                throw new IllegalArgumentException("Unsupported EC point format, expected uncompressed (0x04)");
            }
            
            // 1. Get the standard secp256r1 curve parameters from Java Security
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParams = parameters.getParameterSpec(ECParameterSpec.class);
            
            // 2. Parse the raw EC point bytes into X and Y coordinates (32 bytes each)
            byte[] xBytes = new byte[32];
            byte[] yBytes = new byte[32];
            System.arraycopy(serverPubKeyBytes, 1, xBytes, 0, 32);
            System.arraycopy(serverPubKeyBytes, 33, yBytes, 0, 32);
            
            BigInteger x = new BigInteger(1, xBytes);
            BigInteger y = new BigInteger(1, yBytes);
            ECPoint ecPoint = new ECPoint(x, y);
            
            // 3. Reconstruct the Server's PublicKey object dynamically
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, ecParams);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey serverPublicKey = keyFactory.generatePublic(pubKeySpec);
            
            // 4. Initialize KeyAgreement math engine with our Private Key
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(clientKeyPair.getPrivate());
            
            // 5. Combine Server's Public Key with our Private Key to derive the Shared Secret
            keyAgreement.doPhase(serverPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();
            
            System.out.println("[+] ECDH Math Engine: Combined keys and successfully derived Shared Secret!");
            return sharedSecret;
            
        } catch (Exception e) {
            System.err.println("[-] ECDH Shared Secret Error: " + e.getMessage());
            return null;
        }
    }
}
