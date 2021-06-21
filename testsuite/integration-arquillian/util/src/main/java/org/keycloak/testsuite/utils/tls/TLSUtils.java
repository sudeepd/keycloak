package org.keycloak.testsuite.utils.tls;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;

public class TLSUtils {

   private TLSUtils() {}

   private static final TrustManager TRUST_ALL_MANAGER = new X509TrustManager() {
      public X509Certificate[] getAcceptedIssuers() {
         return null;
      }

      public void checkClientTrusted(X509Certificate[] certs, String authType) {

      }

      public void checkServerTrusted(X509Certificate[] certs, String authType) {
      }
   };

   private static void printBanner(String message) {
      System.out.println("------------------");
      System.out.println(message);
      System.out.println("------------------");
   }

   public static SSLContext initializeTLS() {
      try {
         String keystorePath = System.getProperty("dependency.keystore");;
         if (keystorePath == null) {
            keystorePath = Paths.get(TLSUtils.class.getResource("/keycloak.bcfks").toURI()).toAbsolutePath().toString(); // when executed directly from IDE without Maven
         }

         printBanner(Security.getProvider("BCFIPS") != null ? "BCFIPS" : "Non fips");
         printBanner("Initializing TLS with keystore " + keystorePath);

         KeyStore keystore = KeyStore.getInstance("bcfks");
         try (FileInputStream is = new FileInputStream(keystorePath)) {
            keystore.load(is, "averylongpassword".toCharArray());
         }
         KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
         keyManagerFactory.init(keystore, "averylongpassword".toCharArray());
         KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

         String truststorePath = System.getProperty("dependency.truststore");;
         if (truststorePath == null) {
            truststorePath = Paths.get(TLSUtils.class.getResource("/keycloak.truststore.bcfks").toURI()).toAbsolutePath().toString(); // when executed directly from IDE without Maven
         }

         printBanner("Initializing TLS with truststore" + truststorePath);

         // Essentially, this is REQUEST CLIENT AUTH behavior. It doesn't fail if the client doesn't have a cert.
         // However it will challenge him to send it.
         KeyStore truststore = KeyStore.getInstance("bcfks");
         try (FileInputStream is = new FileInputStream(truststorePath)) {
            truststore.load(is, "averylongpassword".toCharArray());
         }
         TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
         trustManagerFactory.init(truststore);
         TrustManager[] trustManagers = new TrustManager[trustManagerFactory.getTrustManagers().length + 1];
         for (int i = 0; i < trustManagerFactory.getTrustManagers().length; ++i) {
            trustManagers[i] = trustManagerFactory.getTrustManagers()[i];
         }
         trustManagers[trustManagers.length - 1] = TRUST_ALL_MANAGER;

         SSLContext sslContext;
         sslContext = SSLContext.getInstance("TLS");
         sslContext.init(keyManagers, trustManagers, null);
         return sslContext;
      } catch (Exception e) {
         throw new IllegalStateException("Could not initialize TLS", e);
      }
   }
}

