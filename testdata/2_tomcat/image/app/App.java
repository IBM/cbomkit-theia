import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

// Some basic code to create a TLS connection to a server

public class App {
    public static void main(String[] args) {
        System.out.println("Hello, World!");

        try {
            // Create a SSLSocketFactory with the desired SSL/TLS protocol and cipher suite
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket("google.com", 443);

            // Enable 3DES_EDE_CBC cipher suite
            String[] enabledCipherSuites = { "TLS_RSA_WITH_3DES_EDE_CBC_SHA" }; // This cipher suite is vulnerable and disabled by default in OpenJDK 22 
            // throws: javax.net.ssl.SSLHandshakeException: No appropriate protocol (protocol is disabled or cipher suites are inappropriate) --> this is an error imposed by the java.security configuration

            socket.setEnabledCipherSuites(enabledCipherSuites);

            // Perform the TLS handshake
            socket.startHandshake();

            // Your code to communicate over the TLS connection

            // Close the socket when done
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}