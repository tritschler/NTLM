package com.tritschler.ntlm;

/**
 * Build NTLM Messages type1 and type3.
 * 
 * The idea is to first create an NTLMMessage object (constructor), then
 * use the setters methods to set the message parameters and finally to
 * call the buildMessage() method.
 * <br>Be carefull because there is NO enforcement mechanism for the setters.
 * 
 * @author <a href="mailto:marc.tritschler@c-w.be">marc.tritschler@c-w.be</a>
 */
public class NTLMMessage {

    /* public constants */
	
	public static final String NTLM_TYPE1 = "1";
	public static final String NTLM_TYPE2 = "2";
	public static final String NTLM_TYPE3 = "3";
	    
	public static final String ENC_ASCII   = "a";
	public static final String ENC_UNICODE = "u";	
	
	/* private constants */
	    
	private static final byte [] NTLM_SIGNATURE = new byte [] {
	    	'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00 };
	    
	private static final byte [] NTLM_MSGTYPE_1 = new byte [] {
	    	0x01, 0x00, 0x00, 0x00 };
	    
	private static final byte [] NTLM_MSGTYPE_2 = new byte [] {
	     	0x02, 0x00, 0x00, 0x00 };
	    
    private static final byte [] NTLM_MSGTYPE_3 = new byte [] {
	    	0x03, 0x00, 0x00, 0x00 };

    /* default type1 flags */
	    
	private static final byte [] TYPE1_DEFAULT_FLAGS =  new byte [] {
	    	0x07, (byte)0xb2, (byte)0x08, (byte)0xa0 };
	    
	/* default type3 flags */
	    
	private static final byte [] TYPE3_DEFAULT_FLAGS =  new byte [] {
	    	0x05, (byte)0x82, (byte)0x88, (byte)0xa0 };
	    	
	/* constant lengths */
	
	private static final byte SECBUFF_LEN      = 8;      	
	private static final byte LM_RESP_LEN      = 24;   
	private static final byte NTLM_RESP_LEN    = 24;   	
	private static final byte NTLMv2_RESP_LEN  = (byte)146;
	private static final byte CHALLENGE_LEN    = 8;
	private static final byte FLAGS_LEN        = 4;                       
		
	/* constant offsets */
	
	private static final int NTLMSSP_SIGN_OFFSET               =   0;
	private static final int NTLM_MSGTYPE_OFFSET               =   8;	    
	    
	/* type1 constant offsets */
	
	private static final int T1_FLAGS_OFFSET                   =  12;       
	private static final int T1_DOMAIN_SECBUFF_OFFSET          =  16;
	private static final int T1_WORKSTATION_SECBUFF_OFFSET     =  24;
	private static final int T1_WORKSTATION_OFFSET             =  32;
	 
	/* type2 constant offsets */
	private static final int T2_CHALLENGE_OFFSET               =  24;
	
	/* type3 constant offsets */
	
	private static final int T3_LM_SECBUFF_OFFSET              =  12;       
	private static final int T3_NTLM_SECBUFF_OFFSET            =  20;
	private static final int T3_DOMAIN_SECBUFF_OFFSET          =  28;
	private static final int T3_USER_SECBUFF_OFFSET            =  36;
	private static final int T3_WORKSTATION_SECBUFF_OFFSET     =  44;
	private static final int T3_SESSIONKEY_SECBUFF_OFFSET      =  52;
	private static final int T3_FLAGS_OFFSET                   =  60;
	private static final int T3_DOMAIN_OFFSET                  =  64;
	
	/* NTLM Levels */
	
	private static final int NTLM_LEVEL1 = 1;  /* LM/NTLM                 */
	private static final int NTLM_LEVEL2 = 2;  /* Client Challenge/NTLMs2 */
	private static final int NTLM_LEVEL3 = 3;  /* LMv2/NTLMv2             */
	
	/* MAX message lengths */
	
	private static final int TYPE1_MAX_LEN = 100;    /* normal ~ 50 bytes */
	private static final int TYPE2_MAX_LEN = 200;    /* normal ~ 150 bytes*/
	private static final int TYPE3_MAX_LEN = 200;    /* normal ~ 150 bytes*/
	
	/* internal variables */
	
	private String type;                             /* type1 or type3    */
	private String encode;                           /* ASCII or UNICDOE) */
	private byte [] type3 = new byte[TYPE3_MAX_LEN]; /* type3 buffer      */
	private byte [] type1 = new byte[TYPE1_MAX_LEN]; /* type1 buffer      */
	private byte [] type2 = new byte[TYPE2_MAX_LEN]; /* type2 buffer      */
	private byte [] flags = new byte [FLAGS_LEN];    /* flags             */
	private String domain;                           /* windows domain    */
	private String user;                             /* user              */
	private String pass;                             /* user password     */
	private String workstation;                      /* workstation       */
	private byte [] challenge;                       /* type2 challenge   */
	private byte [] client_challenge;                /* client challenge  */
	private int ntlm_level;                          /* NTLM_LEVEL1, 2, 3 */
	private byte [] targetinfo = new byte [88];      /* target info type2 */
	private int msglen;                              /* message length    */ 
	    
	/* public methods (API) */
	    
	/**
	 * Constructor for type1 & type3
	 * @param type Type of NTLM message (NTLM_TYPE1 or NTLM_TYPE3)
	 */
	public NTLMMessage (String msgtype) {	    
		this.type = msgtype;
	    if (type.equals(NTLM_TYPE3)) {
	    	
	    	/* default values for type3 */
	    	
	    	this.ntlm_level = NTLM_LEVEL2;
	    	this.encode = ENC_UNICODE;
	    	this.flags = TYPE3_DEFAULT_FLAGS;
	    	this.client_challenge = getClientChallenge();
	    }
	    else if (type.equals(NTLM_TYPE1)) {
	    	
	    	/* default values for type1 */
	    		
	    	/* domain & wokstation MUST be sent as ASCII in type1 msg */
	    	this.encode = ENC_ASCII;
	    	this.flags = TYPE1_DEFAULT_FLAGS;
	    }
	}
	/**
	 * Constructor for NTLM type2
	 * @param type
	 * @param buffer
	 */
	public NTLMMessage (String type, String buffer) {
		this.type2 = Base64.decode64(buffer);       	
        this.challenge = HexBuff.getBytes(type2,
        		                         T2_CHALLENGE_OFFSET, 
        		                         T2_CHALLENGE_OFFSET + CHALLENGE_LEN);
        for (int k=0; k<88; k++) this.targetinfo[k] = type2[k+74];        
        HexBuff.dumpBuff(type2);    	
    	System.out.println("Challenge:");
    	HexBuff.dumpBuff(this.challenge);
    	System.out.println("Target Info(" + this.targetinfo.length + " bytes)");
    	HexBuff.dumpBuff(this.targetinfo);
	}
	/**
	  * API method to set the Windows domain
	  * @param domain Windows domain
	  */
    public void setDomain(String domain) {
	    	this.domain = domain;
	}
    /**
      * API method to set the workstation
      * @param wks
      */
	public void setWorkstation(String wks) {
	    this.workstation = wks;
	}
	/**
	  * API method to set the user
	  * @param proxy_user
	  */
    public void setUser(String proxy_user) {
	    	this.user = proxy_user;
	}
    /**
     * API method to set the password
     * @param pass
     */
    public void setPassword(String pass) {
    	this.pass = pass;
    }
	/**
	 * API method to set the challenge received
	 * in the type2 message
	 * @param c Challenge (8 bytes)
	 */
    public void setChallenge(byte [] c) {
	    this.challenge = c;
	}
	/**
	 * API method to set the flag field of the NTLM message
	 * @param f Flag
	 */
    public void setFlags(byte [] f) {
	    this.flags = f;
	}
	/**
	 * API method to set the target info received
	 * in type2 message
	 * @param t Target info buffer
	 */
    public void setTargetInfo(byte [] t) {
	        this.targetinfo = t;	
	    }
	/**
	 * Set the encoding type (ENC_ASCII or ENC_UNICODE)
	 * This setter is 'optional' for type3 (default set to UNICODE in the
	 * constructor) and should not be used with type1 (always ASCII).
	 * @param enc_type
	 */
    public void setEncoding(String enc_type) {
        if (this.type.equals(NTLM_TYPE3))
        	    this.encode = enc_type;
    }
    /**
     * Return the challenge received in type2 message
     * @return Challenge
     */
    public byte [] getChallenge() {    	
    	return this.challenge;
    }            
    /**
	 * Build the NTLM message (type1 or type3)
	 * Should be called only after all setters are used.
	 * (be carefull because this is not enforced)
	 * @return NTLM message
	 */
	public String buildMessage () throws Exception {
	
	    if (this.type.equals(NTLM_TYPE3))	{
	        	
	       	/* type3 */
	        	
	       	/* NTLM Signature */
	        	
	       	System.arraycopy ( NTLM_SIGNATURE,
                               0,
                               this.type3,
                               NTLMSSP_SIGN_OFFSET,
                               NTLM_SIGNATURE.length );
	        	
	        /* Message type */
	        	
	        System.arraycopy ( NTLM_MSGTYPE_3,	        			
	        		           0, 
	        		           this.type3,
	        		           NTLM_MSGTYPE_OFFSET,
	        		           NTLM_MSGTYPE_3.length );
	        	
	        /* Security Buffer 1 (LM) */
	        	
	        System.arraycopy ( getSecurityBuffer(LM_RESP_LEN,getLMOffset()), 
	        			       0,
	        			       this.type3,	        			           
	        			       T3_LM_SECBUFF_OFFSET,
	        			       SECBUFF_LEN );
	        	
	        /* Security Buffer 2 (NTLM) */
	        	
	        System.arraycopy ( getSecurityBuffer(NTLM_RESP_LEN,getNTLMOffset()),
	        		           0,
	        		           this.type3,
	        		           T3_NTLM_SECBUFF_OFFSET,
	        		           SECBUFF_LEN );
	        	
	        /* Security Buffer 3 (domain) */
	        	
	        System.arraycopy ( getSecurityBuffer ( getStringLength(this.domain),
	        			                           getDomainOffset()),
	        			       0,
	        			       this.type3,	        			        
	        			       T3_DOMAIN_SECBUFF_OFFSET,
	        			       SECBUFF_LEN );
	        	
	        /* Security Buffer 4 (user) */
	        	
	    	System.arraycopy ( getSecurityBuffer ( getStringLength(this.user),
                                                   getUserOffset()),
	    	    		       0,
	    	    		       this.type3,
	    	    		       T3_USER_SECBUFF_OFFSET,
	    	    		       SECBUFF_LEN );
	    	    
	    	/* Security Buffer 5 (workstation) */
	    	    
	    	System.arraycopy ( getSecurityBuffer (
	    	    		                      getStringLength(this.workstation),
	    	    		                      getWorkstationOffset()),
	    	    		       0,
	    	    		       this.type3,
	    	    		       T3_WORKSTATION_SECBUFF_OFFSET,
	    	    		       SECBUFF_LEN );
	    	    
	    	/* Security Buffer 6 (Session Key) */
	    	    
	    	System.arraycopy ( getSecurityBuffer(0, getSessionKeyOffset()),   
	    	   		           0,
	    	   		           this.type3,
	    	   		           T3_SESSIONKEY_SECBUFF_OFFSET,
	    	   		           SECBUFF_LEN);
	    	/* Flags */
	    	    
	    	System.arraycopy ( flags,                                           
	    	   		           0,
	    	   		           this.type3,
	    	   		           T3_FLAGS_OFFSET,
	    	   		           FLAGS_LEN );
	    	
	    	/* Domain */
	    	    
	    	System.arraycopy ( getBytes(this.domain),
	    	   		           0,
	    	   		           this.type3,
	    	   		           T3_DOMAIN_OFFSET,
	    	   		           getStringLength(this.domain));
	    	    
	    	/* User */
	    	    
	    	System.arraycopy ( getBytes(this.user.toUpperCase()),	    	    		
	    	   		           0,
	    	   		           this.type3,
	    	   		           getUserOffset(),
	    	   		           getStringLength(this.user));
	    	    
	    	/* Workstation */
	    	    
	    	System.arraycopy ( getBytes(this.workstation),	    	    		
	    	   		           0,
	    	   		           this.type3,	    	    		           
	    	   		           getWorkstationOffset(),
	    	   		           getStringLength(this.workstation));	    	    
	    	    
	    	/* LM */
	    	    
	    	System.arraycopy ( buildLMField(),
	    	   		           0,
	    	   		           this.type3,
	    	   		           getLMOffset(),	    	 
	    	   		           LM_RESP_LEN);
	    	    
	    	/* NTLM */
	    	    
	    	System.arraycopy ( buildNTLMField(),
	    	  		           0,
	    	   		           this.type3,
	    	   		           getNTLMOffset(),
	    	   		           NTLM_RESP_LEN);
	    	    
	        /* copy type3 in a byte array of exact length */
	        	
	        this.msglen = getSessionKeyOffset();	        	  
	        byte [] out = new byte [this.msglen];
	        System.arraycopy(this.type3, 0, out, 0, this.msglen);
	        //Helper.dumpBuff(out);
	        return Base64.encode64(out);	
	    }
	    else {
	        	
	       	/* type1 /*
	        	
	       	/* NTLM Signature */
	        	
	        System.arraycopy ( NTLM_SIGNATURE,
                               0,
                               this.type1,
                               NTLMSSP_SIGN_OFFSET,
                               NTLM_SIGNATURE.length );
	        	
	        /* Message type */
	        	
	        System.arraycopy ( NTLM_MSGTYPE_1,                                
	        		           0,
	        		           this.type1,
	        		           NTLM_MSGTYPE_OFFSET,
	        		           NTLM_MSGTYPE_1.length );	        	
	    	
	        /* Flags */
	    	    
	    	System.arraycopy ( this.flags,                                           
	    	   		           0,
	    	   		           this.type1,
	    	   		           T1_FLAGS_OFFSET,
	    	   		           FLAGS_LEN );
	        	
	    	/* Security Buffer 1 (domain) */
	        	
	        System.arraycopy ( getSecurityBuffer ( getStringLength(this.domain),
	        			                           getDomainOffset()),
	        			       0,
	        			       this.type1,	        			        
	        			       T1_DOMAIN_SECBUFF_OFFSET,
	        		           SECBUFF_LEN );
	    	    
	    	/* Security Buffer 2 (workstation) */
	        	
	        System.arraycopy ( getSecurityBuffer ( 
                                              getStringLength(this.workstation),
                                              getWorkstationOffset()),
                               0,
                               this.type1,	        			        
                               T1_WORKSTATION_SECBUFF_OFFSET,
                               SECBUFF_LEN );
	        	
	        /* Workstation */
	        	
	        System.arraycopy ( getBytes(this.workstation),                        
                               0,
                               this.type1,	        			        
                               getWorkstationOffset(),
                               getStringLength(this.workstation) );
	        	
	        /* Domain */
	        	
	        System.arraycopy ( getBytes(this.domain),                        
                               0,
                               this.type1,	        			        
                               getDomainOffset(),
                               getStringLength(this.domain) );

	        /* copy type1 in a byte array of exact lengths */
	        	
	        int buffsize = getDomainOffset() + getStringLength(this.domain);
	        byte [] out = new byte [buffsize];
	        System.arraycopy(this.type1, 0, out, 0, buffsize);
	        //Helper.dumpBuff(out);
	        return Base64.encode64(out);
	    }
    }
        
	/* Non API methods (private) */
	    
	/**
	 * Create pseudo random challenge (8 bytes)
	 * Note: this client challenge is required in NTLM level2 but
	 * the applet does no security check on it. So no worry.
	 * @return 8 random bytes
	 */
	private byte [] getClientChallenge() {		
	    byte [] out = new byte [8];
	    for (int i=0; i<8; i++) {
	        out[i] = (byte) (Math.random() * 255);
	    }
	    return out;
	}	    
	/**
	 * Wrapper method returning the ASCII or UNICODE encoding
	 * of given string
	 * @param s String to convert
	 * @return ASCII or UNICODE representation
	 * @throws Exception
	 */
	private byte [] getBytes(String s) throws Exception {	    	
	   	try {
	        if (this.encode.equals(ENC_ASCII))
	    	    return s.getBytes("ASCII7");
	    	else
	    	    return s.getBytes("UnicodeLittleUnmarked");
	    }
	    catch (Exception e) {
	    	throw e;
	    }
	}
	/**
	 * Compute the offset of the Domain field in a type1 or type3 message
	 * @return Domain offset
	 */
	private int getDomainOffset() throws Exception {
	    if (this.type.equals(NTLM_TYPE3)) {
			
			/* type3 : Domain is at fixed position */
			
		    return T3_DOMAIN_OFFSET;
		}
		else {
			
			/* type1 : Domain is after Workstation */
			
			return ( T1_WORKSTATION_OFFSET + 
					         getStringLength(this.workstation));
		}
	}
	private int getWorkstationOffset() throws Exception {
	    if (this.type.equals(NTLM_TYPE1)) {
			
			/* type1 : workstation is at fixed position */
			
		    return T1_WORKSTATION_OFFSET;
		}
		else {
			
			/* type3 : workstation is after user */
			
			return  ( getUserOffset() + 
					        getStringLength(this.user));
		}
	}
	private int getUserOffset() throws Exception {
	
	    /* type3 : workstation is after domain */
			
        return (getDomainOffset() + getStringLength(this.domain));
		
	}
	/**
	 * Compute the offset of the imaginary session key, just after
	 * the NTLM response.
	 * @return
	 */
	private int getSessionKeyOffset() throws Exception {
	    if (this.ntlm_level == NTLM_LEVEL3) {
	    		
	        /* level 3 : NTLM response is 146 bytes */
	    		
	    	return (getNTLMOffset() + NTLMv2_RESP_LEN);
	    }	    			    	
	    else {
	    		
	    	/* level 1 & 2 : NTLM response is 24 bytes */
	    		
	    	return (getNTLMOffset() + NTLM_RESP_LEN);
	    }
	}
	/**
	 * Compute the offset of the NTLM response within type3 message.
	 * The NTLM response is right after the LM response.
	 * @return NTLM response offset
	 */
    private int getNTLMOffset() throws Exception {
        return (getLMOffset() + LM_RESP_LEN);
	}

	/**
	 * Compute the offset of the LM response within the type3 message.
	 * The offset is dependent of the length of 3 variable length fields
	 * preceding the LM response in the type3 message.
	 * @param domain
	 * @param user
	 * @param workstation
	 * @param code
	 * @return LM response offset
	 */
    private int getLMOffset() throws Exception {	    	
	    return ( getWorkstationOffset() +
	    		       getStringLength(this.workstation));                   	                 	    
    }	    
	/**
	 * Build the LM field of the type3 message.
	 * The contents of this field depends on the 'level'.
	 * @return LM field
	 */
    private byte [] buildLMField() throws Exception {
	    byte [] nulb = new byte [] { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	    byte [] lm = new byte [LM_RESP_LEN];

	        if (this.ntlm_level == NTLM_LEVEL1) {
	    	    	
	    	    /* LM field contains the lm response */
	                
	    	    lm = NTLMType3Responses.getLMResponse ( this.pass,
	                		                            this.challenge );
	    	}
	    	else if (this.ntlm_level == NTLM_LEVEL2) {
	    	    	
	    	   	/* LM field contains the client_challenge (8 bytes)
	    	       followed by 16 zeros */
	    	    	
	    	    System.arraycopy( this.client_challenge, 
	    	    		          0,
	    	    		          lm,
	    	    		          0,
	    	    		          CHALLENGE_LEN);
	    	    	
	    	    System.arraycopy( nulb, 0, lm, CHALLENGE_LEN, nulb.length);  	    	
	    	}
	    	else if (this.ntlm_level == NTLM_LEVEL3) {
	    	    	
	    	    /* LM field contains the LMv2 response */

	    	    return NTLMType3Responses.getLMv2Response (
	    	                     this.domain, 
	    	    			     this.user,
	    	    			     this.pass,
	    	    			     this.challenge,
	    	    			     this.client_challenge);
	    	}
	    return lm;
	}
	/**
	 * Build the NTLM field of the type3 message.
	 * The contents of this field depends on the 'level'.
	 * @return NTLM field
	 */
    private byte [] buildNTLMField() throws Exception {    	    	
        if (this.ntlm_level == NTLM_LEVEL1) {
    	    return NTLMType3Responses.getNTLMResponse(
    	        		            this.pass,
    	        		            this.challenge);    
    	}
    	else if (this.ntlm_level == NTLM_LEVEL2) {
    	    return NTLMType3Responses.getNTLM2SessionResponse(
    		    		            this.pass,
    		    		            this.challenge,
    		    		            this.client_challenge); 
    	}
    	else {
            return NTLMType3Responses.getNTLMv2Response( 
                		            this.domain,
                		            this.user,
                		            this.pass,
                		            this.targetinfo,
                		            this.challenge,
                		            this.client_challenge);
        }	    	   	            			    	   
	}	   
	/**
	 * Return a string length based on the encoding type
	 * (ASCII: 1 byte/letter, Unicode: 2 bytes/letter)
	 * @param s String to process
	 * @return String length
	 */
    private int getStringLength(String s) throws Exception {
        if (this.encode.equals(ENC_ASCII))
		    return s.getBytes("ASCII").length;
	    else
	        return s.getBytes("UnicodeLittleUnmarked").length;
    }
    /**
	* Build a Security Buffer
	* A security buffer is always 8 bytes and is a 'pointer' to a
    * variable length buffer.
    * Its structure is:
    * - 2 bytes (little endian) : length of the buffer
    * - 2 bytes (little endian) : allocated space (usually same as length)
    * - 4 bytes (little endian) : offset of the buffer in the message
	* @param len Length of the buffer pointed by the security buffer
	* @param offset Offset within the type3 message of the buffer pointed
	* @return Security Buffer
	*/
	private byte [] getSecurityBuffer(int len, int offset) {			
	    return new byte [] { 
	        (byte)len, 0x00, (byte)len, 0x00, (byte)offset, 0x00, 0x00, 0x00 };
	}	   
}
