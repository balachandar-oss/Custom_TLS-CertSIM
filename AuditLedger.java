import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;

public class AuditLedger {

    // Sharing the same local SQLite database file
    private static final String DB_URL = "jdbc:sqlite:cipherwire.db";

    public AuditLedger() {
        initializeLedger();
    }

    /**
     * Connects to SQLite and creates the Audit Log table if it doesn't exist.
     */
    private void initializeLedger() {
        String createTableSQL = "CREATE TABLE IF NOT EXISTS handshake_audit_log ("
                              + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                              + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, "
                              + "target_host TEXT, "
                              + "negotiated_cipher TEXT, "
                              + "cert_status TEXT, "
                              + "latency_ms INTEGER"
                              + ");";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
             
            stmt.execute(createTableSQL);
            System.out.println("[+] AuditLedger: Handshake log table validated in database.");
            
        } catch (Exception e) {
            System.err.println("[-] AuditLedger Initialization Error: " + e.getMessage());
        }
    }

    /**
     * Records a completed or failed TLS handshake into the database.
     */
    public void logHandshake(String targetHost, String negotiatedCipher, String certStatus, long latencyMs) {
        String insertSQL = "INSERT INTO handshake_audit_log (target_host, negotiated_cipher, cert_status, latency_ms) VALUES (?, ?, ?, ?)";
        
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {
             
            pstmt.setString(1, targetHost);
            pstmt.setString(2, negotiatedCipher);
            pstmt.setString(3, certStatus);
            pstmt.setLong(4, latencyMs);
            
            pstmt.executeUpdate();
            System.out.println("[+] AuditLedger: Handshake metadata securely logged to cipherwire.db");
            
        } catch (Exception e) {
            System.err.println("[-] AuditLedger Logging Error: " + e.getMessage());
        }
    }
}
