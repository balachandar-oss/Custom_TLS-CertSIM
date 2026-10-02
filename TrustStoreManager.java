import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class TrustStoreManager {

    private static final String DB_URL = "jdbc:sqlite:cipherwire.db";

    public TrustStoreManager() {
        initializeDatabase();
    }

    /**
     * Connects to SQLite and creates the Trust Store table if it doesn't exist.
     */
    private void initializeDatabase() {
        // We add a UNIQUE constraint to common_name to prevent duplicate seeding
        String createTableSQL = "CREATE TABLE IF NOT EXISTS trusted_root_cas ("
                              + "id INTEGER PRIMARY KEY, "
                              + "common_name TEXT UNIQUE, "
                              + "public_key_hex TEXT"
                              + ");";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
             
            stmt.execute(createTableSQL);
            System.out.println("[+] TrustStoreManager: SQLite Database initialized successfully.");
            
        } catch (Exception e) {
            System.err.println("[-] TrustStoreManager Initialization Error: " + e.getMessage());
        }
    }

    /**
     * Seeds the database with the Google Trust Services "WE2" Root CA.
     */
    public void seedGoogleRootCA() {
        String insertSQL = "INSERT OR IGNORE INTO trusted_root_cas (common_name, public_key_hex) VALUES (?, ?)";
        
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {
             
            pstmt.setString(1, "WE2");
            // The real SubjectPublicKeyInfo (SPKI) Hex for Google Trust Services "GTS CA WE2"
            pstmt.setString(2, "3059301306072A8648CE3D020106082A8648CE3D03010703420004357E1FF214ED907DE19E2A344386C1D596E82770DF9E04CBA9CA86790B084D468AC274A4BBD9BFEEFD23D738F34BEF5417E1BEE7CA5525A80C30AC2D5D4EA151");
            pstmt.executeUpdate();
            
            System.out.println("[+] TrustStoreManager: Seeded WE2 Root CA into local trust store.");
            
        } catch (Exception e) {
            System.err.println("[-] TrustStoreManager Seeding Error: " + e.getMessage());
        }
    }

    /**
     * Retrieves the Public Key Hex for a given Common Name.
     */
    public String getPublicKeyByCN(String commonName) {
        String querySQL = "SELECT public_key_hex FROM trusted_root_cas WHERE common_name = ?";
        
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(querySQL)) {
             
            pstmt.setString(1, commonName);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("public_key_hex");
                }
            }
            
        } catch (Exception e) {
            System.err.println("[-] TrustStoreManager Query Error: " + e.getMessage());
        }
        
        System.out.println("[-] TrustStoreManager: Issuer '" + commonName + "' NOT FOUND in Trust Store!");
        return null; // Not found
    }

    // Quick internal test
    public static void main(String[] args) {
        TrustStoreManager tsm = new TrustStoreManager();
        tsm.seedGoogleRootCA();
        String we2Key = tsm.getPublicKeyByCN("WE2");
        System.out.println("[+] Retrieved Key for WE2: " + we2Key);
    }
}
