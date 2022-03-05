package com.tritschler.ntlm;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;

public class CertificateManager {
	
    private static final String CERTIFICATEHEADER     = "-----BEGIN CERTIFICATE-----";
	private static final String CERTIFICATEFOOTER     = "-----END CERTIFICATE-----";
	private static final String CRLF                  = "\r\n";
	
	private String      keystore_name;
	private String      certificate;
	private String      passw;
	private String      alias;
	
	public CertificateManager(String path, String cert, String passw, String alias) {
		
	    this.keystore_name = path;
	    this.certificate = cert;
	    this.passw = passw;
	    this.alias = alias;
	    
	}

	/**
	 * Install the certificate in the keystore
	 * 
	 */
	public String install() {
       
	   String errmsg = createCertificateFile();
       if (!errmsg.equals("")) {
    	    return ("Unable to create certifcate file: " + keystore_name + "(" + errmsg + ")");
       }
    	   
       try {
           KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
    	   CertificateFactory cf = CertificateFactory.getInstance("X.509");
     	   java.security.cert.Certificate c = cf.generateCertificate((InputStream)new FileInputStream(keystore_name));
     	   keystore.load(null, passw.toCharArray());
	       keystore.setCertificateEntry(alias, c);
	       FileOutputStream out = new FileOutputStream(keystore_name);
	       keystore.store(out, passw.toCharArray());
	       out.close();
	       return "";
	   }
       catch (Exception e) {    	    
           return ("Exception: " + e.getMessage());
       }     
   }	
	
	 /**
     * Create a certificate file (RFC 1421 - Base64 encoding) named
     * oasys.cer in the java.home/jre/lib/security directory and
     * containing the given certificate.
     *
     * @param cert the certificate (Base64 encoded) to save
     * @return true if success, false if error
     */
	private String createCertificateFile() {
		
	   File tmp = new File(keystore_name);
	   try {
		   tmp.delete();
		   FileOutputStream outstream = new FileOutputStream(keystore_name);
		   outstream.write((CERTIFICATEHEADER + CRLF).getBytes());
		   for (int i=0; i < certificate.length()/64; i++) {			
		       outstream.write((certificate.substring(i*64,(i+1)*64) + CRLF ).getBytes());
		   }
		   outstream.write(
				 ( certificate.substring(
						 ((certificate.length()/64))*64,
				         ((certificate.length()/64))*64 + certificate.length()%64) + CRLF
				 ).getBytes());		   
		   outstream.write(CERTIFICATEFOOTER.getBytes());
		   outstream.close();
	   } catch (Exception e) {		   		     
		     return e.getMessage();   
	   }
	   return "";
   }


	
	
}
