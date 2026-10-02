import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class ClientHelloBuilder {

    public static byte[] buildClientHello(String targetHost) {
        ByteBuffer buffer = ByteBuffer.allocate(512); // Increased buffer size for extensions

        // 1. TLS RECORD HEADER (5 Bytes)
        buffer.put((byte) 0x16);
        buffer.putShort((short) 0x0301);
        int recordLengthPos = buffer.position();
        buffer.putShort((short) 0);       

        // 2. HANDSHAKE HEADER (4 Bytes)
        buffer.put((byte) 0x01);
        int handshakeLengthPos = buffer.position();
        buffer.put((byte) 0x00);
        buffer.putShort((short) 0);

        // 3. CLIENT HELLO PAYLOAD
        buffer.putShort((short) 0x0303); // Legacy Client Version
        
        byte[] clientRandom = new byte[32];
        new SecureRandom().nextBytes(clientRandom);
        buffer.put(clientRandom);

        buffer.put((byte) 0x00); // Session ID Length (0)

        // Cipher Suites
        buffer.putShort((short) 6);       // Length: 6 bytes (3 suites)
        buffer.putShort((short) 0x1301);  // TLS_AES_128_GCM_SHA256 (TLS 1.3)
        buffer.putShort((short) 0xC02B);  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
        buffer.putShort((short) 0xC02F);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
        // Compression Methods
        buffer.put((byte) 0x01);
        buffer.put((byte) 0x00);

        // ==========================================
        // 4. THE EXTENSIONS BLOCK
        // ==========================================
        int extensionsLengthPos = buffer.position();
        buffer.putShort((short) 0); // Placeholder for total extensions length

        // --- Extension 1: Server Name Indication (SNI) ---
        byte[] hostBytes = targetHost.getBytes();
        buffer.putShort((short) 0x0000); // Extension Type: SNI
        
        int sniListLen = 1 + 2 + hostBytes.length; // Type(1) + NameLen(2) + HostBytes
        int sniExtLen = 2 + sniListLen;            // ListLen(2) + SniListLen
        
        buffer.putShort((short) sniExtLen);        // Extension Length
        buffer.putShort((short) sniListLen);       // Server Name List Length
        buffer.put((byte) 0x00);                   // Name Type: host_name
        buffer.putShort((short) hostBytes.length); // Name Length
        buffer.put(hostBytes);                     // "google.com"

        // --- Extension 2: Supported Groups (Elliptic Curves) ---
        buffer.putShort((short) 0x000A); // Type: supported_groups (10)
        buffer.putShort((short) 0x0004); // Length: 4 bytes
        buffer.putShort((short) 0x0002); // List Length: 2 bytes
        buffer.putShort((short) 0x0017); // secp256r1 (23)
        
        // --- Extension 3: EC Point Formats ---
        buffer.putShort((short) 0x000B); // Type: ec_point_formats (11)
        buffer.putShort((short) 0x0002); // Length: 2 bytes
        buffer.put((byte) 0x01);         // List Length: 1 byte
        buffer.put((byte) 0x00);         // uncompressed (0)
        
        // --- Extension 4: Signature Algorithms ---
        buffer.putShort((short) 0x000D); // Type: signature_algorithms (13)
        buffer.putShort((short) 0x0006); // Length: 6 bytes
        buffer.putShort((short) 0x0004); // List Length: 4 bytes
        buffer.putShort((short) 0x0403); // ecdsa_secp256r1_sha256
        buffer.putShort((short) 0x0401); // rsa_pkcs1_sha256

        // --- Backfill Extensions Length ---
        int extensionsLength = buffer.position() - extensionsLengthPos - 2;
        buffer.putShort(extensionsLengthPos, (short) extensionsLength);

        // ==========================================
        // 5. BACKFILL RECORD & HANDSHAKE LENGTHS
        // ==========================================
        int endPosition = buffer.position();

        int handshakeLength = endPosition - handshakeLengthPos - 3;
        buffer.put(handshakeLengthPos + 1, (byte) ((handshakeLength >> 8) & 0xFF));
        buffer.put(handshakeLengthPos + 2, (byte) (handshakeLength & 0xFF));

        int recordLength = endPosition - recordLengthPos - 2;
        buffer.putShort(recordLengthPos, (short) recordLength);

        byte[] finalPayload = new byte[endPosition];
        buffer.rewind();
        buffer.get(finalPayload);

        return finalPayload;
    }
}