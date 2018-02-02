/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * Originally from:
 * http://blogs.sun.com/andreas/resource/InstallCert.java
 * Use:
 * java InstallCert hostname
 * Example:
 *% java InstallCert ecc.fedora.redhat.com
 */

import javax.net.ssl.*;

import org.apache.commons.io.FilenameUtils;
import org.apache.cxf.configuration.security.KeyStoreType;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.context.embedded.undertow.FileSessionPersistence;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.SocketFactory;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Class used to add the server's certificate to the KeyStore
 * with your trusted certificates.
 * USAGE: <hostname>:<port> <password_keystore> <path_to_keystore> 
 * e.g. localhost:443 changeit 
 * e.g. InstallCert 192.168.72.87:5050 changeit /opt/alfresco-4.2.f/java/jre/lib/security/cacerts
 * e.g. localhost:443 changeit C:\Program Files\Java\jdk1.7.0_55\jre\lib\security\cacerts
 * e.g. /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-2.b17.el7_1.x86_64/jre/bin/java InstallCert localhost:443 changeit /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-2.b17.el7_1.x86_64/jre/lib/security/cacerts
 * e.g. localhost:443 changeit C:\Program Files\Java\jdk1.7.0_55\jre\lib\security\cacerts
 * e.g. /usr/local/jdk1.8.0_60/jre/bin/java InstallCert localhost:443 password testInternoTestKeystore.jks
 * e.g. /opt/alfresco-community/java/bin/java InstallCert 159.213.238.75:443 changeit /opt/alfresco-community/java/lib/security/cacerts
 * e.g. /opt/alfresco-community/java/bin/java InstallCert 159.213.238.75:443 changeit /opt/alfresco-community/alf_data/keystore/ssl.truststore 
 */
public class InstallCert {
	
	private static BouncyCastleProvider provider = new BouncyCastleProvider();

    public static void main(String[] args) throws Exception {
    
    	System.setProperty("http.proxySet", "true");
        System.setProperty("http.proxyHost", "192.168.1.188");
        System.setProperty("http.proxyPort", "3128");
        System.setProperty("https.proxyHost", "192.168.1.188");
        System.setProperty("https.proxyPort", "3128");
        
        System.setProperty("https.protocols", "SSL,TLSv1,SSLv3");
        
        boolean installPhisicalCertificate = false;
    	
    	String host = null;
        int port = 0;
		String pathKeyStore;
        char[] passphrase = null;
        String certfile = null;
        String alias = null;
        String password = null;
        //Installiamo il certificato da un server remoto
        if ((args.length == 1) || (args.length == 2) || (args.length == 3)) {
            String[] c = args[0].split(":");
            host = c[0];
            port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
            String p = (args.length == 1) ? "changeit" : args[1];
            passphrase = p.toCharArray();
            
            if(args.length >= 3){
            	pathKeyStore = args[2];
            }else{
            	pathKeyStore = System.getProperty("java.home");
            }
    		System.out.println("HOST:" + host + ",PORT:"+ port + ",PASSPHRASE:" + passphrase.toString() + ",PATHKEYSTORE:" + pathKeyStore);
        } 
        //Installiamo il certificato fisico test.crt
        else  if(args.length == 4){ 
        	installPhisicalCertificate = true;
        	certfile = args[0];//"yourcert.cer"; /*your cert path*/      
	        alias = args[1];//"youralias";
	        String p = (args[2]==null || args[2].isEmpty()) ? "changeit" : args[2];
	        password = p;//yourKeyStorePass";
	        pathKeyStore = args[3];     
        }else {
            System.out.println("Usage: java InstallCert <host>[:port] [passphrase] [path to security folder]");
            return;
        }
		
        File file = new File("jssecacerts");        
        if (file.isFile() == false) {
            char SEP = File.separatorChar;
            File dir;
            
            if(pathKeyStore.toLowerCase().trim().endsWith("jks")){
            	file = new File(pathKeyStore);           
	            if (file.isFile() == false) {
                	throw new IOException("Not exists any keystore JKS of default under the keystore path:" + pathKeyStore);
	            }
            }else if(pathKeyStore.toLowerCase().trim().endsWith("p12")){
            	file = new File(pathKeyStore);           
	            if (file.isFile() == false) {
                	throw new IOException("Not exists any keystore P12 of default under the keystore path:" + pathKeyStore);
	            }
            }else if(pathKeyStore.toLowerCase().trim().endsWith(SEP + "ssl.truststore") || pathKeyStore.toLowerCase().trim().endsWith(SEP + "ssl.keystore")){
            	file = new File(pathKeyStore);           
	            if (file.isFile() == false) {
                	throw new IOException("Not exists any keystore ssl under the keystore path:" + pathKeyStore);
	            }     
            }else{
	            //if path is under XXX/lib/security/ do set
	            if(pathKeyStore.contains(SEP + "lib" + SEP + "security")){
	            	dir = new File(pathKeyStore);	            	
	            }else{
	            	dir = new File(pathKeyStore + SEP + "lib" + SEP + "security");
	            }
	            //if path is under XXX/lib/security/jssecacerts or XXX/lib/security/cacerts do set
	            if(pathKeyStore.contains(SEP + "jssecacerts") || pathKeyStore.contains(SEP + "cacerts")){
	            	file = dir;
	            }
	            else{
		            file = new File(dir, "jssecacerts");
		            if (file.isFile() == false) {
		                file = new File(dir, "cacerts");
		                if (file.isFile() == false){
		                	throw new IOException("Not exists any keystore of default 'jssecacerts' or 'cacerts' under the keystore path:" + pathKeyStore);
		                }
		            }
	            }
            }
        }
        System.out.println("Loading KeyStore " + file + "...");
        InputStream in = new FileInputStream(file);
        //TODO gestire java.io.IOException: Invalid keystore format JKS,PKCS12
        
        //TODO gestire errore di scrittura java.io.IOException: DerInputStream.getLength(): lengthTag=78
        //KeyStore.getInstance("PKCS12");
        
        String ext = FilenameUtils.getExtension(file.getAbsolutePath().toString());
        KeyStore ks = null;
        if(ext.equalsIgnoreCase("JKS")){
        	ks = KeyStore.getInstance("JKS");//JKS,PKCS12 KeyStore.getDefaultType()      	
        }else if(ext.equalsIgnoreCase("P12")){
        	ks = KeyStore.getInstance("PKCS12");//JKS,PKCS12 KeyStore.getDefaultType()
        }else{
        	ks = KeyStore.getInstance(KeyStore.getDefaultType());
        }
		//ks.load(new FileInputStream( certPath ), certPasswd.toCharArray() );
        ks.load(in, passphrase);
        in.close();
        
        if(installPhisicalCertificate){
        	FileInputStream is = new FileInputStream(pathKeyStore);//yourKeyStore.keystore	
  	        passphrase = password.toCharArray();
  	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
  	        InputStream certstream = fullStream (certfile);
  	        Certificate certs =  cf.generateCertificate(certstream);
        	 // Add the certificate
	        Certificate certificate = ks.getCertificate(alias);
	        ks.setCertificateEntry(alias, certs);	        
	        Key key = ks.getKey(alias, passphrase);
	        
	        if(file.exists()){	        
		        listCertificate(file,password);
	
		        OutputStream out = new FileOutputStream(file);
		        ks.store(out, passphrase);
		        out.close();
		        
		        X509Certificate certX05 = (X509Certificate) certs;
		        String dn = certX05.getSubjectX500Principal().getName();
		        LdapName ldapDN = new LdapName(dn);
		        for(Rdn rdn: ldapDN.getRdns()) {
		            System.out.println("DN:" + rdn.getType() + " -> " + rdn.getValue());
		        }
		    
		        System.out.println("The phisical certificate <" + certfile +"> is been importd in the keystore <"+ pathKeyStore + "> with alias <" + alias + ">\r\n");
	        }
        }else{
	//    	Socket sock = new Socket("192.168.1.1", 3128);
	//    	doHandshakeTunnel(sock, host, port);
	
	        SSLContext context = SSLContext.getInstance("SSL");//TSL,SSL
	        
	        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	        tmf.init(ks);
	        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
	        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);    
	        /*
	        //TRUST ALL CERTIFICATE Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {			
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {return new java.security.cert.X509Certificate[0];}
				public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
				public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
			} };
			//TRUST ALL HOST Ignore differences between given hostname and certificate hostname
		    HostnameVerifier hv = new HostnameVerifier(){public boolean verify(String hostname, SSLSession session) { return true; }};	 
	        context.init(null, trustAllCerts, new SecureRandom());
	        HttpsURLConnection.setDefaultHostnameVerifier(hv);
		    HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
	        */
	             
	        context.init(null, new TrustManager[]{tm}, null);

	        InetAddress address = InetAddress.getByName(host);
	        System.out.println("Opening connection to " + host + ":" + port + " with InetAdress: "+address.toString()+" ...");
	        //SSLSocketFactory factory = new SSLSocketFactory(context,SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
	        javax.net.ssl.SSLSocketFactory factory = context.getSocketFactory();
	        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
	        //SSLSocket socket = (SSLSocket)factory.getDefault().createSocket(host, port);
	        socket.setEnabledProtocols(new String[]{"SSLv3", "TLSv1.1","SSL"});
	        socket.setSoTimeout(60000);
	        try {
	            System.out.println("Starting SSL handshake...");
	            //doHandshakeTunnel(socket, host, port);
	            socket.startHandshake();
	            socket.close();
	            System.out.println();
	            System.out.println("No errors, certificate is already trusted");
	        } catch (SSLException e) {
	            System.out.println();
	            e.printStackTrace(System.out);
	        }
	
	        X509Certificate[] chain = tm.chain;
	        if (chain == null) {
	            System.out.println("Could not obtain server certificate chain");
	            return;
	        }
	
	        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	
	        System.out.println();
	        System.out.println("Server sent " + chain.length + " certificate(s):");
	        System.out.println();
	        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
	        MessageDigest md5 = MessageDigest.getInstance("MD5");
	        for (int i = 0; i < chain.length; i++) {
	            X509Certificate cert = chain[i];
	            System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
	            System.out.println("   Issuer  " + cert.getIssuerDN());
	            sha1.update(cert.getEncoded());
	            System.out.println("   sha1    " + toHexString(sha1.digest()));
	            md5.update(cert.getEncoded());
	            System.out.println("   md5     " + toHexString(md5.digest()));
	            System.out.println();
	        }
	
	        System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
	        String line = reader.readLine().trim();
	        int k;
	        try {
	            k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
	        } catch (NumberFormatException e) {
	            System.out.println("KeyStore not changed");
	            return;
	        }
	
	        X509Certificate cert = chain[k];  
	        
	        boolean aliasIsAlreadySaved = false;
	        Enumeration enumeration = ks.aliases();
	        while(enumeration.hasMoreElements()) {
	            String myalias = (String)enumeration.nextElement();
	            if(myalias.equalsIgnoreCase(host)){
	            	aliasIsAlreadySaved = true;
	            	break;
	            }
	            //Certificate certificate = keystore.getCertificate(alias);
	        }
	        String myalias2="";
	        if(aliasIsAlreadySaved){
	        	myalias2 = host + "-" + (k + 1);
	        }else{
	        	myalias2 = host;
	        }
	
	        ks.setCertificateEntry(myalias2, cert);
	
	        OutputStream out = new FileOutputStream(file);
	        ks.store(out, passphrase);
	        out.close();
	
	        System.out.println();
	        System.out.println(cert);
	        System.out.println();
	        System.out.println("Added certificate to keystore '"+pathKeyStore+"' using alias '"+ myalias2 + "'");
	        
	        System.out.println("Other infromation");
	        
	        //List<Collection<List<?>>> asList = Arrays.asList(cert.getSubjectAlternativeNames());
			//System.out.println("List of Hostnames:" + asList.toArray().toString());
	        
	        //System.out.println("List of Hostnames:" + getSubjectAlternativeNames(cert));
	        
	//        x500name x500name = new CertificateHolder(cert).getSubject();
	//        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
	//        IETFUtils.valueToString(cn.getFirst().getValue());
	        
	        //Print the ldap information
	        String dn = cert.getSubjectX500Principal().getName();
	        LdapName ldapDN = new LdapName(dn);
	        for(Rdn rdn: ldapDN.getRdns()) {
	            System.out.println("DN:" + rdn.getType() + " -> " + rdn.getValue());
	        }
			System.out.println("My Hostnames:" +InetAddress.getByName(host).getHostName() + " or " + InetAddress.getByName(host).getCanonicalHostName()); 
        }	        
    }

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {       
	        /* 
	         * This change has been done due to the following resolution advised for Java 1.7+
			 * http://infposs.blogspot.kr/2013/06/installcert-and-java-7.html
	         */ 
        	return new X509Certificate[0];	
            //throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
    
    /**
     * Using the following code it is possible to add a trust store during runtime.
     * @param trustStore
     * @param password
     * @throws Exception
     */
    public static void setTrustStore(String trustStore, String password) throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream keystoreStream = InstallCert.class.getResourceAsStream(trustStore);
        keystore.load(keystoreStream, password.toCharArray());
        trustManagerFactory.init(keystore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustManagers, null);
        SSLContext.setDefault(sc);
    }
    
    static void doHandshakeTunnel(Socket tunnel, String host, int port) throws IOException
    {
    	OutputStream out = tunnel.getOutputStream();
    	String msg = "CONNECT " + host + ":" + port + " HTTP/1.0\n"
    	              + "User-Agent: "
    	             + sun.net.www.protocol.http.HttpURLConnection.userAgent
    	             + "\r\n\r\n";
    	byte b[];
    	try {
    	/*
    	* We really do want ASCII7 -- the http protocol doesn't change
    	* with locale.
    	*/
    	   b = msg.getBytes("ASCII7");
    	} catch (UnsupportedEncodingException ignored) {
    	    b = msg.getBytes();
    	}
    	out.write(b);
    	out.flush();

    	byte           reply[] = new byte[200];
    	int            replyLen = 0;
    	int            newlinesSeen = 0;
    	boolean        headerDone = false;     /* Done on first newline */

    	InputStream    in = tunnel.getInputStream();
    	boolean        error = false;

    	while (newlinesSeen < 2) {
    		int i = in.read();
    	    if (i < 0) {
    			throw new IOException("Unexpected EOF from proxy");
    		}
    		if (i == '\n') {
    			headerDone = true;
    			++newlinesSeen;
    		} else if (i != '\r') {
    			newlinesSeen = 0;
    			if (!headerDone && replyLen < reply.length) {
    				reply[replyLen++] = (byte) i;
    			}
    		}
    	}

    	String replyStr;
    	try {
    		replyStr = new String(reply, 0, replyLen, "ASCII7");
    	} catch (UnsupportedEncodingException ignored) {
    		replyStr = new String(reply, 0, replyLen);
    	}

    	//if (!replyStr.startsWith("HTTP/1.0 200")) {
    	if(replyStr.toLowerCase().indexOf(
    		"200 connection established") == -1){
    		throw new IOException("Unable to tunnel through "
    			+ "192.168.1.1" + ":" + 3128
    			+ ".  Proxy returns \"" + replyStr + "\"");
    	}
    }
    
    private static InputStream fullStream ( String fname ) throws IOException {
        FileInputStream fis = new FileInputStream(fname);
        DataInputStream dis = new DataInputStream(fis);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return bais;
    }
    
    //https://gist.github.com/stevebradshaw/4633000
    @SuppressWarnings("unchecked")
	private static void listCertificate(File pathKeyStore, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
    	KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream(pathKeyStore), password.toCharArray());
        Enumeration<String> aliases = keystore.aliases();
        List<String> list= Collections.list(aliases); // create list from enumeration 
        Collections.sort(list);
        aliases = Collections.enumeration(list);       
        while(aliases.hasMoreElements()){
            String alias = aliases.nextElement();
            if(keystore.getCertificate(alias).getType().equals("X.509")){
//            	X509Certificate myCert = (X509Certificate)CertificateFactory.getInstance("X509").generateCertificate(// string encoded with default charset
//                       new ByteArrayInputStream(cert.getBytes())
//                        );
                System.out.println(alias + " expires " + ((X509Certificate) keystore.getCertificate(alias)).getNotAfter());
            }
    	}
    }
    

    
    
}