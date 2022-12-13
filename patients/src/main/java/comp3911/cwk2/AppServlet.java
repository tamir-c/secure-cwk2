package comp3911.cwk2;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

import java.util.Base64;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String AUTH_QUERY = "select * from user where username='%s' and password='%s'";
  private static final String SEARCH_QUERY = "select * from patient where surname='%s' collate nocase";
  private static KeyPair pair = null;
  private static PublicKey publicKey = null;
  private static PrivateKey privateKey = null;
  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    try {
      pair = loadKeyPair();
    } catch (Exception e) {
      e.printStackTrace();
    }
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    try {
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
     // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    try {
      if (authenticated(username, password)) {
        // Get search results and merge with template
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      }
      else {
        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private boolean authenticated(String username, String password) throws SQLException {
    String query = String.format(AUTH_QUERY, username, password);
    try (Statement stmt = database.createStatement()) {
      ResultSet results = stmt.executeQuery(query);
      if (results.next()) {
        String saltString = results.getString("salt");
        String passwordHashFromDb = results.getString("password");
        String hash = Hashing.hashPasswordWithSalt(password, saltString);
        return hash.equals(passwordHashFromDb);
      }
      return false;
    }
  }

  private List<Record> searchResults(String surname) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
    List<Record> records = new ArrayList<>();
    String query = String.format(SEARCH_QUERY, surname);
    try (Statement stmt = database.createStatement()) {
      ResultSet results = stmt.executeQuery(query);
      while (results.next()) {
        Record rec = new Record();

        rec.setSurname(results.getString(2));
        rec.setForename(new String(cipher.doFinal(results.getBytes(3))));
        rec.setAddress(new String(cipher.doFinal(results.getBytes(4))));
        rec.setDateOfBirth(new String(cipher.doFinal(results.getBytes(5))));
        rec.setDoctorId(new String(cipher.doFinal(results.getBytes(6))));
        rec.setDiagnosis(new String(cipher.doFinal(results.getBytes(7))));
        records.add(rec);
      }
    }
    return records;
  }

  private void KeyPairGenerator() throws Exception {
    //Creating KeyPair generator object
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

    //Initializing the KeyPairGenerator
    keyPairGen.initialize(2048);

    //Generating the pair of keys
    pair = keyPairGen.generateKeyPair();
    publicKey = pair.getPublic();
    privateKey = pair.getPrivate();
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
            publicKey.getEncoded());
    FileOutputStream fos = new FileOutputStream("public.key");
    fos.write(x509EncodedKeySpec.getEncoded());
    fos.close();

    // Store Private Key.
    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
            privateKey.getEncoded());
    fos = new FileOutputStream("private.key");
    fos.write(pkcs8EncodedKeySpec.getEncoded());
    fos.close();
    System.out.println("public: " + pair.getPublic() + "\n" + "private: " + pair.getPrivate() + "\n");
  }

  private KeyPair loadKeyPair() throws Exception {
    // Read Public Key.
    File filePublicKey = new File("public.key");
    FileInputStream fis = new FileInputStream("public.key");
    byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
    fis.read(encodedPublicKey);
    fis.close();

    // Read Private Key.
    File filePrivateKey = new File("private.key");
    fis = new FileInputStream("private.key");
    byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
    fis.read(encodedPrivateKey);
    fis.close();

    // Generate KeyPair.
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
            encodedPublicKey);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
            encodedPrivateKey);
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

    return new KeyPair(publicKey, privateKey);
  }

  private void encryptDatabase() throws Exception{
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
    List<Record> records = new ArrayList<>();
    String query = String.format(SEARCH_QUERY, "'or '1' = '1");
    try (Statement stmt = database.createStatement()) {
      ResultSet results = stmt.executeQuery(query);
      int count = 1;
      while (results.next()) {
        if (count > 5){
          results.close();
          break;
        }
        for (int i = 3; i < 8; i++) {
          ResultSetMetaData rsmd = results.getMetaData();
          String colName = rsmd.getColumnName(i);
          byte[] input = results.getString(i).getBytes();
          cipher.update(input);
          byte[] cipherText = cipher.doFinal();
          String REPLACE_QUERY = "update patient set " + colName + "= ? where id= ? ";
          PreparedStatement pstmt = database.prepareStatement(REPLACE_QUERY);
          pstmt.setBytes(1,cipherText);
          pstmt.setInt(2, count);
          pstmt.executeUpdate();
          pstmt.close();
        }
        count++;
      }
    }
  }


  private void decryptDatabase() throws Exception{
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
    String query = String.format(SEARCH_QUERY, "'or '1' = '1");
    try (Statement stmt = database.createStatement()) {
      ResultSet results = stmt.executeQuery(query);
      while (results.next()) {
        for (int i = 3; i < 8; i++) {
          byte[] decipheredText = cipher.doFinal(results.getBytes(i));
          System.out.println(new String(decipheredText) + "\n");
        }
        System.out.println("\n-------End--------\n");
      }
    }
  }
}
