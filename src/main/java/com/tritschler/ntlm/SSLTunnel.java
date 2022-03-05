package com.tritschler.ntlm;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;
//import com.sun.security.auth.module.NTSystem;   // TODO: try to remove to be Windows independent ??


/**
 * <pre>Manage a SSL tunnel through a proxy (if present) to the target server.
 * The idea is to create 1 instance of this class using the constructor,
 * then call the public method setProxy() to set the proxy parameters,
 * then call the public method createTunnel() to create the SSL tunnel to
 * the remote host.
 * Example
 * try {
 *     SSLTunnel ssl = new SSLTunnel(host, port);
 *	   ssl.setProxy ( proxy_host,
 *                    proxy_port,
 *                    proxy_user,
 *                    proxy_pass,
 *                    proxy_domain,
 *                    proxy_wks);
 *		Socket s = ssl.createTunnel();
 *		System.out.println("SSL tunnel created");		    
 *		// ...
 * }
 * catch (Exception e) {
 *	    System.out.println("Unable to create a SSL tunnel to the target.");	   
 *		}</pre>
 *
 * @author Markus
 * 
 */
public class SSLTunnel {	
	
	/* public constants */
	public static final String ERR_AUTH_NOT_SUPPORTED =
		                                "authentication not supported";
	public static final String ERR_PROXY_ERROR        = 
		                                "proxy returned HTTP Status Code: ";
	public static final String ERR_AUTH_FAILED        =
		                                "authentication failed";
    	
	
	/* private variables */
	
	private String proxy_host = "";
    private String proxy_port = "";
    private String proxy_user = "";
    private String proxy_pass = "";
    private String proxy_domain = "";
    private String proxy_workstation = "";    
    private String target_host;
    private String target_port;
    private String hostname;
    private String username;
    private String domain;  
    private String auth_method = "";
    private byte [] challenge;
    private byte [] targetinfo = new byte [88];
    private boolean ssl = true;
    private SSLSocketFactory factory;
    private Socket s1;                         /* normal socket */ 
    private SSLSocket s2;                      /* ssl socket */
    public String ssl_cipher_suite;            /* negotiated SSL Cipher Suite */
	
    /* public methods (API) */ 
	   
    /**
	 * Constructor
	 * @param host The remote host to reach
	 * @param port The remote port 
	 */
    public SSLTunnel(String host, String port, boolean ssl_support) {
    	
	    this.target_host = host;
	    this.target_port = port;   
	    this.ssl = ssl_support;
	      	
	    if (this.ssl) {
	        /* setup the SSLContext first, as there's a lot of
	      	 * computations to be done */
	  	 
	        this.factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
	    }
    }
	/**
	 * API method to Set proxy related variables
	 * @param host Name of the proxy
	 * @param port Port the proxy listen
	 * @param user User to authenticate
	 * @param pass Passowrd
	 * @param domain Windows Domain
	 * @param workstation Workstation name
	 */
    public void setProxy ( String host,
	    		           String port,
	    		           String user,
	    		           String pass,           
	    		           String domain,
	    		           String workstation) {
	    this.proxy_host = host;
	    this.proxy_port = port;
	    this.proxy_user = user;
        this.proxy_pass = pass;
	    this.proxy_domain = domain;
	    this.proxy_workstation = workstation;
	    System.setProperty("https.proxyHost", this.proxy_host);
	    System.setProperty("https.proxyPort", this.proxy_port);
	}
    /**
     * Create an SSL tunnel to the target host through a proxy
     * @return The SSL socket
     * @throws Exception
     */
	public void createTunnel() throws Exception {
	    
	    Socket tunnel;
	    Socket newtunnel;
	    String http_status_code;
	    OutputStream os;
	    BufferedReader is;
	    // https://www.baeldung.com/java-9-http-client
	    Http http = new Http();

   	    /* get hostname, domain and user (Windows only) */
        try {
            InetAddress addr = InetAddress.getLocalHost();
            this.hostname = addr.getHostName();
        }
        catch (UnknownHostException e) {
        	this.hostname = "localhost";
        }
	        
        //NTSystem pc = new NTSystem();
        //this.domain = pc.getDomain();
        //this.username = pc.getName();        
	            
        System.out.println("Host: " + this.hostname + ", User: " + this.username + ", Domain: " + this.domain);
	            


        /* first create a TCP connection to the proxy,
         * and send http connect without authentication */
	    	
	    tunnel = new Socket (this.proxy_host,
	    		             Integer.parseInt((proxy_port)));
	    os = tunnel.getOutputStream();
	    is = new BufferedReader(new InputStreamReader(tunnel.getInputStream()));
	    http.setAuthMethod(Http.AUTH_NONE);
	    http.sendRequest(os, http.buildConnectReq(this.target_host,
	    			                              this.target_port));	    
	    
	    System.out.println("Waiting proxy answer ...");
	    
	    http_status_code = Http.getResponse(is, Http.STATUS_CODE);
	    System.out.println("Received status code:" + http_status_code);
	    
	    if (!http_status_code.equals(Http.HTTP_OK) &&
	    	!http_status_code.trim().equals("")) {
	    	
	    	/* proxy rejected the 1st CONNECT & closed the socket */
	    		
	    	tunnel.close();
	    	if (!http_status_code.equals(Http.HTTP_PROXY_AUTH)) {
	    	    	
	    	    /* proxy rejected the request for another reason than authentication */
	    	    		    	    
	    	    throw new Exception(ERR_PROXY_ERROR + http_status_code);
	    	}
	    	else {
	    		
	    	    /* proxy ask authentication */
	    		
	    	    newtunnel = new Socket( this.proxy_host, 
                                        Integer.parseInt(this.proxy_port));
	    	     
	    	    os = newtunnel.getOutputStream();
	    	    is = new BufferedReader(new InputStreamReader(
		                                    	   newtunnel.getInputStream()));
	    	    if (http.isNTLMAuthSupported()) {
	    	    		
	    	        /* proxy supports NTLM Authentication */
	    	    			    	    	
	    	    	http.sendRequest(os, ntlmBuildType1());
	    	    	http_status_code = http.getResponse(is, http.STATUS_CODE);
	    	    	if (!(http_status_code).equals(Http.HTTP_PROXY_AUTH)) {
	    	    		/* proxy did not answer with 407 */
	    	    		throw new Exception();
	    	    	}
	    	    	NTLMMessage type2 = 
	    	    		new NTLMMessage( NTLMMessage.NTLM_TYPE2,
	    	    			             http.getProxyAuthenticate());
	    	    	this.challenge = type2.getChallenge();	    	    	
	    	    	http.sendRequest(os, ntlmBuildType3());
	    	    	http_status_code = http.getResponse(is, http.STATUS_CODE); 
	    	    	if (!http_status_code.equals(Http.HTTP_OK)) {	        	    	
	        	    	throw new Exception(ERR_AUTH_FAILED);
	        	    }	
	    	    	else {
	    	    		/* NTLM authentication successfull */
	    	    		this.auth_method = Http.AUTH_NTLM;
	    	    	}
	    	    }
	    	    else if (http.isBasicAuthSupported()) {
	    	    		
	    	        /* Basic authentication. Very weak authentication 
	    	    	 * (password sent in clear). Done in last because RFC2617
	    	    	 *  requests to do the strongest supported authentication */
	    	    			    	    		
	    	    	this.auth_method = Http.AUTH_BASIC;
	    	    }
	    	    else {
	    	    	/* authentication not supported */
	    	    	newtunnel.close();
	    	    	throw new Exception(ERR_AUTH_NOT_SUPPORTED);
	    	    }
	    	}	    
	    }
	    else {
	        /* proxy accepted the 1st CONNECT without any 
	    	 * authentication (security problem) */
	        
	    	newtunnel = tunnel;
	    		
	    }	    
	    System.out.println("Proxy connection OK");
	    /* client is authenticated */
	    
	    if (!this.ssl) {
	    	/* no SSL */
	    	this.s1 = newtunnel;
	    }
	    else {
	        /* overlay the tunnel socket with SSL */
	    	
	        this.s2 =
	    		(SSLSocket)factory.createSocket( 
	    				                 newtunnel,
	    	    		                 this.target_host,
	    	    		                 Integer.parseInt(this.target_port),
	    	    		                 true);
	    	    
	        /* register a callback for SSL handshaking completion event
	    
            this.s2.addHandshakeCompletedListener(
	            new HandshakeCompletedListener() {
	    	        public void handshakeCompleted(
	    		        HandshakeCompletedEvent event) {
	    			        System.out.println("Handshake finished!");
	    			        SSLTunnel.this.ssl_cipher_suite = event.getCipherSuite();
	    			        //System.out.println("\t CipherSuite:" + event.getCipherSuite());
	    			        //System.out.println("\t SessionId " + event.getSession());
	    			        //System.out.println("\t PeerHost " + event.getSession().getPeerHost());
	    		        }
	    		    }
	        );*/
	        
            this.s2.startHandshake();
            
	    }
	}
	/**
	 * Return the Socket 'connected' to the remote server (in fact, the socket
	 * is TCP connected to the Proxy and the Proxy is TCP connected to the
	 * server: Client <--TCP--> Proxy <--TCP--> Server)
	 * @return
	 */
	public Socket getSocket() {
		return this.s1;
	}
	/**
	 * Return the SSL socket connected to the remote server (in fact, the socket
	 * is TCP connected to the Proxy and the Proxy is TCP connected to the
	 * server. But, from a SSL point of view, the Client has a SSL session with
	 * the remote server:
	 * Client   <----------SSL----------> Server
	 *          <--TCP--> Proxy <--TCP--> 	 
	 * @return
	 */
	public SSLSocket getSSLSocket() {
		return this.s2;
	}
	/**
	 * Return the SSL negotiated cipher suite
	 * @return SSL Cipher Suite
	 */
	public String getCipherSuite() {
		return this.ssl_cipher_suite;
	}
	/* private methods */    
	 
    /**
	 * Build NTLM type1
	 * @return NTLM type1 string encapsulated in a HTTP CONNECT
	 * @throws IOException (network problem)
	 */    	
    private String ntlmBuildType1() throws Exception {
  	      	    
  	    /* Build the type 1 */
    	
   		NTLMMessage ntlmmsg = new NTLMMessage(NTLMMessage.NTLM_TYPE1);
   		ntlmmsg.setDomain(this.domain);    		
   		ntlmmsg.setWorkstation(this.proxy_workstation);	 
   		String type1 = ntlmmsg.buildMessage();
   		
   		/* encapsulate in HTTP */
   		
   		Http req = new Http();
   		req.setAuthMethod(Http.AUTH_NTLM);
   		req.setAuthToken(type1);	    
   		return req.buildConnectReq(this.target_host, this.target_port);
   		
    }
	    
    /**
	 * Build a NTLM type3
	 * @return NTLM type3 encapsulated in a HTTP CONNECT
	 * @throws IOException
	 */
	private String ntlmBuildType3() throws Exception {	    

        /* build the NTLM type3 */
	    		
	    NTLMMessage ntlmmsg = new NTLMMessage(NTLMMessage.NTLM_TYPE3);	    	
	    ntlmmsg.setDomain(this.domain);
	    ntlmmsg.setUser(this.proxy_user);
	    ntlmmsg.setPassword(this.proxy_pass);
	    ntlmmsg.setWorkstation(this.proxy_workstation);
	    ntlmmsg.setChallenge(this.challenge);
	    //Helper.dumpBuff(this.challenge);

	    /* encapsulate in HTTP */
	    
	    Http req = new Http();
	    String type3 = ntlmmsg.buildMessage();
  		req.setAuthMethod(Http.AUTH_NTLM);
   		req.setAuthToken(type3);	
	    return req.buildConnectReq(this.target_host, this.target_port);
	}		
	    	   
}


