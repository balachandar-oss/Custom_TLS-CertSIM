import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

public class CipherWireClient {

    public static void main(String[] args) {
        String targetHost = "google.com";
        int targetPort = 443;
        String cipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";

        System.out.println("=== Project CipherWire: TLS Simulator ===");
        
        // 1. Initialize local persistent subsystems
        TrustStoreManager trustStore = new TrustStoreManager();
        trustStore.seedGoogleRootCA();
        AuditLedger auditLedger = new AuditLedger();

        // 2. Start execution timer
        long startTime = System.currentTimeMillis();
        String certStatus = "FAILED";

        try (Socket socket = new Socket(targetHost, targetPort)) {
            System.out.println("[+] PHASE 1: TCP Pipeline Opened to " + targetHost + ":" + targetPort);

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // 3. Send ClientHello
            byte[] clientHelloBytes = ClientHelloBuilder.buildClientHello(targetHost);
            System.out.println("[+] Sending ClientHello (" + clientHelloBytes.length + " bytes)...");
            out.write(clientHelloBytes);
            out.flush();

            // 4. Read Server Response
            System.out.println("[+] Waiting for Server response...");
            byte[] responseBuffer = new byte[16384]; 
            int bytesRead = in.read(responseBuffer);
            
            // Allow a small delay to catch all fragmented TCP packets
            try { Thread.sleep(250); } catch (Exception e) {}
            while (in.available() > 0 && bytesRead < responseBuffer.length) {
                bytesRead += in.read(responseBuffer, bytesRead, responseBuffer.length - bytesRead);
            }

            if (bytesRead > 0) {
                System.out.println("[+] SUCCESS: Received " + bytesRead + " bytes from the server!");
                
                ByteBuffer buf = ByteBuffer.wrap(responseBuffer, 0, bytesRead);
                
                boolean phase5Complete = false;
                
                // 5. Parse TLS Records
                while (buf.remaining() >= 5) {
                    byte recordType = buf.get();
                    short recordVersion = buf.getShort();
                    int recordLength = buf.getShort() & 0xFFFF;
                    
                    if (recordType == 0x16) { // Handshake Record
                        int recordEnd = buf.position() + recordLength;
                        
                        while (buf.position() < recordEnd && buf.remaining() >= 4) {
                            byte hsType = buf.get();
                            int hsLen = ((buf.get() & 0xFF) << 16) | ((buf.get() & 0xFF) << 8) | (buf.get() & 0xFF);
                            int startOfMsg = buf.position();
                            
                            if (hsType == 0x0B) { // Certificate Message
                                buf.position(buf.position() + 3); // Skip Cert List Length
                                int cert1Len = ((buf.get() & 0xFF) << 16) | ((buf.get() & 0xFF) << 8) | (buf.get() & 0xFF);
                                
                                System.out.println("\n[+] Found Certificate Message! First Cert is " + cert1Len + " bytes.");
                                ByteBuffer derBuf = buf.slice();
                                derBuf.limit(cert1Len);
                                
                                // Traverse tree and extract signature logic
                                DerParser.parseNode(derBuf, 0);
                                
                                System.out.println("\n[+] Querying local SQLite Trust Store for 'WE2' Public Key...");
                                String we2PubKeyHex = trustStore.getPublicKeyByCN("WE2");
                                
                                if (we2PubKeyHex != null) {
                                    boolean isValid = DerParser.verifySignature(DerParser.tbsCertificateBytes, DerParser.signatureBytes, we2PubKeyHex);
                                    certStatus = isValid ? "VERIFIED" : "SIGNATURE_MISMATCH";
                                }
                                buf.position(startOfMsg + hsLen); // Safely advance buffer
                                
                            } else if (hsType == 0x0C) { // ServerKeyExchange Message
                                System.out.println("\n[+] Found ServerKeyExchange Message! Parsing ECDHE Parameters...");
                                
                                byte curveType = buf.get();        // 0x03 for named_curve
                                short namedCurve = buf.getShort(); // 0x0017 for secp256r1
                                int pubKeyLen = buf.get() & 0xFF;  // Length of EC point
                                
                                byte[] serverPubKeyBytes = new byte[pubKeyLen];
                                buf.get(serverPubKeyBytes);
                                System.out.println("[+] Extracted Server Ephemeral Public Key (" + pubKeyLen + " bytes)");
                                
                                // Phase 5: Diffie-Hellman Key Derivation
                                KeyExchangeManager kem = new KeyExchangeManager();
                                byte[] sharedSecret = kem.generateSharedSecret(serverPubKeyBytes);
                                
                                System.out.println("[+] Phase 5 Complete! Master Shared Secret Length: " + sharedSecret.length + " bytes");
                                
                                buf.position(startOfMsg + hsLen); // Safely advance buffer
                                phase5Complete = true;
                                break; // We got the secret, exit the handshake loop
                                
                            } else {
                                buf.position(startOfMsg + hsLen); // Skip other handshake messages
                            }
                        }
                        if (phase5Complete) break; // Exit record loop, we are fully authenticated and keyed!
                    } else {
                        buf.position(buf.position() + recordLength); // Skip non-handshake records
                    }
                }
            } else {
                System.out.println("[-] Server abruptly closed the connection.");
            }

        } catch (Exception e) {
            System.err.println("[-] Fatal Network Error: " + e.getMessage());
            certStatus = "NETWORK_ERROR";
        }

        // 8. Stop timer and securely log the event to our Audit Ledger
        long latencyMs = System.currentTimeMillis() - startTime;
        auditLedger.logHandshake(targetHost, cipherName, certStatus, latencyMs);
        
        System.out.println("=== Simulation Complete ===");
    }
}
