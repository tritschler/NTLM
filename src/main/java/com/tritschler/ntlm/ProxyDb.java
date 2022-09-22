package com.tritschler.ntlm;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Filter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import netscape.javascript.JSObject;

/**
 * Applet acting as a SQL proxy over SSL session
 * 
 */

public class ProxyDb  {
	
	private static final long serialVersionUID          = 1L;
		
	private static final String COMPANY                 = "company";
	private static final String APPLICATION             = "myapp";
	private static final String MODULE                  = "applet";	

	private static final String DSN_DEFAULT_NAME        = "ATSI";
	private static final String DSN_DEFAULT_USER        = "user1";
	private static final String DSN_DEFAULT_PASS        = "tbd";
		
	// Applet parameters names : change them carefully because some names 
	// are in the HTML page and others may be in local configuration file.
	
	private static final String PARAM_PROXY_HOST        = COMPANY + "." + APPLICATION + "." + MODULE + "." + "proxy.host";
	private static final String PARAM_PROXY_PORT        = COMPANY + "." + APPLICATION + "." + MODULE + "." + "proxy.port";
	private static final String PARAM_PROXY_DOMAIN      = COMPANY + "." + APPLICATION + "." + MODULE + "." + "proxy.domain";
	private static final String PARAM_PROXY_USER        = COMPANY + "." + APPLICATION + "." + MODULE + "." + "proxy.user";	
	private static final String PARAM_PROXY_PASSWORD    = COMPANY + "." + APPLICATION + "." + MODULE + "." + "proxy.password";
	private static final String PARAM_PROXY_WORKSTATION = COMPANY + "." + APPLICATION + "." + MODULE + "." + "proxy.workstation";	
	private static final String PARAM_DSN_NAME          = COMPANY + "." + APPLICATION + "." + MODULE + "." + "dsn.name";
	private static final String PARAM_DSN_USER          = COMPANY + "." + APPLICATION + "." + MODULE + "." + "dsn.user";
	private static final String PARAM_DSN_PASS          = COMPANY + "." + APPLICATION + "." + MODULE + "." + "dsn.pass";
	private static final String PARAM_HOST              = COMPANY + "." + APPLICATION + "." + MODULE + "." + "host";
	private static final String PARAM_PORT              = COMPANY + "." + APPLICATION + "." + MODULE + "." + "port";
	private static final String PARAM_TOKEN             = COMPANY + "." + APPLICATION + "." + MODULE + "." + "token";
	private static final String PARAM_CERT              = COMPANY + "." + APPLICATION + "." + MODULE + "." + "cert";
	private static final String PARAM_SSL               = COMPANY + "." + APPLICATION + "." + MODULE + "." + "ssl";
	private static final String PARAM_LOG_CONSOLE       = COMPANY + "." + APPLICATION + "." + MODULE + "." + "log.console";
	private static final String PARAM_LOG_FILE          = COMPANY + "." + APPLICATION + "." + MODULE + "." + "log.file";
	private static final String PARAM_KEYSTORE          = COMPANY + "." + APPLICATION + "." + MODULE + "." + "keystore.name";
	private static final String PARAM_KEYSTORE_ALIAS    = COMPANY + "." + APPLICATION + "." + MODULE + "." + "keystore.alias";
	private static final String PARAM_KEYSTORE_PASS     = COMPANY + "." + APPLICATION + "." + MODULE + "." + "keystore.pass";
	
	private static final int    RC_ERROR                = -1;
	private static final int    RC_OK                   =  0;
	private static final int    MAX_DELAY               = 60;            
	private static final long   MAX_LOGFILE_SIZE        = 1000000;  
	private static final String SSL_CIPHER_1            = "SSL_RSA_WITH_3DES_EDE_CBC_SHA "; 	
	private static final String YES                     = "yes";
	private static final String NO                      = "no";	

	private static final String CERT_INSTALLED          = "Certificate installed";
	private static final String CONN_DB_OK              = "Applet connected to local DB";
	private static final String PROXY_OK                = "Proxy Authenticated";
	private static final String SSL_SESSION_OK          = "SSL established with: ";
	private static final String INVALID_MSG             = "invalid message";
	private static final String CERT_NOT_INSTALLED      = "Faild to install Certificate";
	private static final String CALL_HELPDESK           = "Please contact the help desk";
        private static final String WAIT_REQUEST            = "waiting request from Server ...";
	private static final String ERR_NO_AUTH_OK          = "Applet authentication failure with Server.";
	private static final String ERR_AUTH_OK             = "Applet did not expect AUTH_OK";
	private static final String ERR_DB_CONNECT          = "Applet can't connect to local DB.";
	private static final String ERR_SSL_INVALID_SUITE   = "Invalid SSL Cipher Suite";
	private static final String DB_OK                   = "DB access OK";
	
	private   static String ssid = "";
	private   static String           homeDir           = "";
	private   static String           keyStore;
	private   static int              nInstances        = 0;
	protected static Logger           logger;
	private   static String           logfile;
	private   static PrintWriter      pw;
	private   static ResultSet        rs;	        		 
	private   static Connection       con;
	private   static Statement        stmt;	
	private          Sql              current_sql       = new Sql();		
	private          String           error_severe      = "";
	private          int              conn_delay        = 4;
	private          ConsoleHandler   hdlr_cons;
	private          FileHandler      hdlr_file;
	private          HashMap          params            = new HashMap();	
	private          JSObject         MainWindow;
	private          boolean          isSsl;
	
	private class Sql {
		private static final String SP = " ";
		private static final String WHERE = "WHERE";
		private static final String SELECT = "SELECT";
		private static final String FROM = "FROM";
		private String query = "";
		private String method = "";
		private String fields = "";
		private Sql() {
			query = "";
			method = "";
			fields = "";
		}
		public void setQuery(String q) {
			if (q.equals("")) {
				query = "";
				method = "";
				fields = "";
			}
			else {
			    query = q.trim();
			    method = query.substring(0, query.indexOf(SP));
			    fields = query.substring( query.indexOf(" ") + 1, query.toUpperCase().indexOf(FROM)).trim();
			}
		}
		private String getFields() {
			return fields;
		}
	}	
	
	/*
	 //Constructor only needed when extending Thread (for tests)	  	 
	public ProxyDb(HashMap hashmap) {		
		error_severe = "";
		setDefaults();
        params.putAll(hashmap);
	}*/
	
	/**
	 * Set default values to ALL parameters
	 */
    private void setDefaults() {	
	
	    params.put(PARAM_PROXY_DOMAIN,        "");
	    params.put(PARAM_PROXY_HOST,          "");
	    params.put(PARAM_PROXY_PORT,          "");
	    params.put(PARAM_PROXY_USER,          "");
	    params.put(PARAM_PROXY_PASSWORD,      "");
	    params.put(PARAM_PROXY_WORKSTATION,   "");
	    params.put(PARAM_DSN_NAME,            DSN_DEFAULT_NAME);
	    params.put(PARAM_DSN_USER,            DSN_DEFAULT_USER);
	    params.put(PARAM_DSN_PASS,            DSN_DEFAULT_PASS);
	    params.put(PARAM_HOST,                "");
	    params.put(PARAM_PORT,                "");
	    params.put(PARAM_TOKEN,               "");
	    params.put(PARAM_CERT,                "");
	    params.put(PARAM_SSL,                 YES);
	    params.put(PARAM_LOG_CONSOLE,         YES);
	    params.put(PARAM_LOG_FILE,            NO);	    
	    params.put(PARAM_KEYSTORE,            "");
	    params.put(PARAM_KEYSTORE_ALIAS,      APPLICATION);
	    params.put(PARAM_KEYSTORE_PASS,       APPLICATION);	    
	    
    }
    
	/**
	 * Applet initialization
	 * Obtain parameters, install server certificate (if SSL)
	 * connect to DSN
	 */
    
	public void init() {
               
		nInstances++;		
		error_severe = "";
		setDefaults();
		if ((homeDir=getWorkingDir()) == null) {
			System.out.println("No directory with write access found (using defaults, no logging)");
		}
		else {
		   keyStore = homeDir + File.separator + "mykeystore.ks";
		   params.put(PARAM_KEYSTORE, keyStore);
		   logfile = homeDir + File.separator + APPLICATION + ".log";
		}
		
        if (nInstances == 1) {
		    logger = Logger.getLogger(getClass().getPackage().getName());	        
            logger.setUseParentHandlers(false);                        
        }
        //MainWindow = JSObject.getWindow(this);
        //MainWindow.call("hideId", new String [] { "appletmsg"} );
		getServerParams();
		if (nInstances == 1) {
			startLogging();
		    if (logfile != null) {
		    	try {
		    		pw = new PrintWriter(new FileOutputStream(new File(logfile),true), true);
		    	} catch (Exception e) {
		    		severe("failed to acquire a printwriter for " + logfile);
		    	} 
		    }
		}
		info("------------------- Applet starting (" + this.hashCode()+ ") ------------------- "); 
		info("Host: " + (String)params.get(PARAM_HOST) + ":" +  (String)params.get(PARAM_PORT));
		info("Working dir : " + homeDir);
		if (nInstances == 1) { 
			loadConfigFile();			
            if (!setupSsl()) return;        
		}
	}
	
	private boolean setupSsl() {	
		isSsl = (((String)params.get(PARAM_SSL)).equals(YES));
		
        if (isSsl) {
        	
            // SSL 
        	      
     	    System.setProperty("javax.net.ssl.trustStore", keyStore);
     	    System.setProperty("javax.net.ssl.trustStorePassword", (String)params.get(PARAM_KEYSTORE_PASS));
     	
     	    CertificateManager cer = new CertificateManager(
     	    	    (String)params.get(PARAM_KEYSTORE), 
     	    	    (String)params.get(PARAM_CERT),
     	    		(String)params.get(PARAM_KEYSTORE_PASS),
     	    		(String)params.get(PARAM_KEYSTORE_ALIAS));
     	    
     	    String errmsg = cer.install();
     	    if (!errmsg.equals("")) {
     	        	
     	        // failed to install certificate
     	        	
     	    	severe(errmsg);
     	    	MainWindow.call("displaymessage", new String [] {errmsg + " " + CALL_HELPDESK});
     	        return false;
     	        
     	    }
     	    else {
     	    	    
     	       	// certifiacte installed 
     	        	
        	     info(CERT_INSTALLED);
        	     return true;
     	    }
        }
        
	    return true;
	}
	
	/**
	 * Try to connect to the DSN using local or default DSN parameters
	 * In case of failure set the error description in member variable
	 * error_severe but does not terminate yet. The applet will try to
	 * send this error as a first message in order to inform the Server
	 * 
	 */
    private String connectDatabase() {
     	    	
     	try {
            Class.forName("sun.jdbc.odbc.JdbcOdbcDriver");
            if (con != null) con.close();            
        	con = DriverManager.getConnection("jdbc:odbc:" +
        		      (String)params.get(PARAM_DSN_NAME),
        			  (String)params.get(PARAM_DSN_USER),
        			  (String)params.get(PARAM_DSN_PASS));
        	
        	stmt = con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        	
        	info(CONN_DB_OK + " (DSN=" + (String)params.get(PARAM_DSN_NAME) + ")");
        	return "";
        }
     	catch (Exception e) {     	         		
     		error_severe = ERR_DB_CONNECT + " DSN=" +(String)params.get(PARAM_DSN_NAME) + e.getMessage();     		                          		                          		                     
     		severe(error_severe);
     		if (pw != null) e.printStackTrace(pw);
         	return error_severe;
     	}                        		
	}

    /**
     * Start the console and file logginq according to the parameters.
     * In case of error, does not terminate because the applet is able 
     * to work without logging facilities.
     */
	private void startLogging() {
				
   		try {
	        
   			// console logging
	        
	        if (params.get(PARAM_LOG_CONSOLE).equals(YES)) {	        
	            hdlr_cons = new ConsoleHandler();	
	            //hdlr_cons.setFormatter(new LogFormatter());
	            hdlr_cons.setFilter(new Filter() {
	                public boolean isLoggable(LogRecord record) {
	                    return true;
	                }
	            });
	            logger.addHandler(hdlr_cons);
	        }
	        
	        // file logging 
	        
	        if (params.get(PARAM_LOG_FILE).equals(YES) && logfile != null) {	        	          	       
	            checkSize(logfile, MAX_LOGFILE_SIZE);	        	  
	            hdlr_file = new FileHandler(logfile, true);
	            //hdlr_file.setFormatter(new LogFormatter());
	            hdlr_file.setFilter(new Filter() {
	                  public boolean isLoggable(LogRecord record) {
	                      return true;
	                  }
	            });
	            logger.addHandler(hdlr_file);    
	          }	        
   		}
   		catch (Exception e) {		   
			System.out.println("exception in startLogging() : " + logfile + e.getMessage());			
   		}        	
	}
	
	/**
	 * Load Proxy, DSN and Keystore parameters from config file
	 * Each line of the config file is either a comment (starts with //),
	 * an empty line or has the format: param = value
	 * Unknown parameters are ignored.
	 * 
	 */
	private void loadConfigFile() {
		
		String           line;
		String           param_name;
		StringTokenizer  st;
		
		
		if (homeDir == null) return;
		
		String cfgfile = homeDir + File.separator + "oasys.cfg"; 
		
	    File f = new File(cfgfile);	    
	    
	    try {
	    	if (f.exists() && f.isFile() && f.canRead()) {
	            BufferedReader r = new BufferedReader(new FileReader(f));
			    while ((line = r.readLine()) != null) {		        
			    	if ((!line.startsWith("//")) && (line.length()>0)) {
			    		st = new StringTokenizer(line, "=");
			    		if (st.countTokens() >= 2) {
			    			param_name = st.nextToken().trim();
			    			if (params.containsKey(param_name)) {
			    				params.put(param_name, st.nextToken().trim());
			    			}
			    		}
			    	}
		        }
                r.close();
                info("loaded configuration file " + cfgfile);
	    	}
	    	else {
	    		warning("no config file found (or no read access) in " + homeDir + ": using defaults");
	    	}	    	
	    } catch (Exception e) {
	    	severe("Exception" + e.getMessage() + " (using defaults)");
	    }
	}
		
	/**
	 * Compute the delay to wait before attempting to connect to Server
	 *  
	 * @return The delay (in seconds)
	 */
	private int getDelay() {
    	if ((conn_delay *=2) > MAX_DELAY) {
    		return MAX_DELAY;
    	}
    	else {
    		return (conn_delay);
    	}
    }
      

	/*private String getParameter(String name) {					        
        return (String)params.get(name);        
	}*/
	
    /*public void run(){
	    init();
	    start();
	   //try { Thread.sleep(100000); } catch (Exception e) {}	
    }*/
    
    /**
     * main logic
     */
    public void start() {
    	
        //Message                    msgin         = null;
        //Message                    msgout        = null;
        String                     msg_id;                  
        String                     flds = "";
        Socket                     socket = null;
        SSLSocket                  ssl_socket;
        ObjectOutputStream         oos;
        ObjectInputStream          ois;
        //com.oasys.applet.commons.DbTable   rec;
        int                        start_rec;            // index of first record requested 
    	int                        max_recs;             // max nb records requested
    	int                        tot_nr_rec = 0;       // total nb records of 1 resultset
    	int                        nb_recs;              // nb of records to send
    	String                     errmsg;
        			        
    	if (ssid.equals((String)params.get(PARAM_TOKEN))) {
    		return;
    	}
    	else {
    		ssid = (String)params.get(PARAM_TOKEN);
    	}
    	
	    if (error_severe.equals("")) {
	    	
	    	// no fatal error occured at init
	    	
    	    info("session: " + (String)(params.get(PARAM_TOKEN)) + " starting");
        
		    // try to create communication link with server 
		
            try {	
		        if (params.get(PARAM_PROXY_HOST).equals("")) {
				
				    // no proxy 
				
		    	    if (isSsl) {
					
				        // SSL
				    
					    SSLSocketFactory factory =
						    (SSLSocketFactory)SSLSocketFactory.getDefault();
					
					    ssl_socket = (SSLSocket)factory.createSocket(
							  (String)params.get(PARAM_HOST),
							  Integer.parseInt((String)params.get(PARAM_PORT)));
					
				        ssl_socket.startHandshake();
				        socket = (Socket)ssl_socket;
                        info(SSL_SESSION_OK + (String)params.get(PARAM_HOST) + ":" + (String)params.get(PARAM_PORT));				                       
				}
				else {
					
					// no SSL 
					
					SocketFactory factory = (SocketFactory)SocketFactory.getDefault();		            
					socket = (Socket)factory.createSocket((String)params.get(PARAM_HOST), Integer.parseInt((String)params.get(PARAM_PORT)));					
					//info(TCP_CONNECTION_OK + (String)params.get(PARAM_HOST) + ":" + (String)params.get(PARAM_PORT));
					info("Obtained " + socket.toString());
				}
			}
			else {
							
			    // proxy 
				
				SSLTunnel ssl = new SSLTunnel(
						(String)params.get(PARAM_HOST),
						(String)params.get(PARAM_PORT), 
						isSsl);
				
		        ssl.setProxy ( (String)params.get(PARAM_PROXY_HOST),
		        		       (String)params.get(PARAM_PROXY_PORT),
		        		       (String)params.get(PARAM_PROXY_USER),
		        		       (String)params.get(PARAM_PROXY_PASSWORD),
		        		       (String)params.get(PARAM_PROXY_DOMAIN),
		        		       (String)params.get(PARAM_PROXY_WORKSTATION));			    
		        
		        ssl.createTunnel();		        
		        
		        info(PROXY_OK);
				
		        if (isSsl) {
					
				    // SSL 
			        
					ssl_socket = ssl.getSSLSocket();
                    socket = (Socket)ssl_socket;
                    info(SSL_SESSION_OK + (String)params.get(PARAM_HOST) + ":" + (String)params.get(PARAM_PORT));                    
			    }
				else {
					
					// no SSL 
					
					socket = ssl.getSocket();
					info("Obtained socket: " + socket.toString());
				}
			}
			
		    conn_delay = (int) (Math.random()*5 + 1);							
					    		    
			oos = new ObjectOutputStream(socket.getOutputStream());
		    ois = new ObjectInputStream(socket.getInputStream());
		    		    
		    /*
		     * handshake (AUTH_REQ / AUTH_OK / APPLET_READY)
		     */
			    
			// send AUTH_REQ 
	    			    
		    send(oos, new Message(Message.MSG_AUTH_REQ, (String)(params.get(PARAM_TOKEN))));	        

			// expect AUTH_OK 
			    
			msgin = receive(ois);
            
			if (!(msgin.validate(Message.TYPE_CLIENT).equals(Message.OK))) {
				
			}
			
			/*if (!msgin.getType().equals(Message.MSG_AUTH_OK)) {
			        
			    // received other message than AUTH_OK 			        
			    			    
			    terminate(RC_ERROR, ERR_NO_AUTH_OK, CALL_MENSURA);
			    return;
			}*/
			
	        // send APPLET_READY 
			   
            //send(oos, new Message(Message.MSG_APPLET_READY, (String)(params.get(PARAM_TOKEN))));
			
			//TODO: remove after test !!!
			
			/*try {
				int x = new Random().nextInt(5)*1000;
				System.out.println("Thread " + getName() + " sleeping " + x + " s");
				Thread.sleep(x);
				return;
			} catch (Exception e) {}*/
			
		    //  main loop (requests / responses) 							
            	
			while (true) {
					
			    // wait requests (read blocking) 
				
				info(WAIT_REQUEST);
				
				msgin = receive(ois);				
																					    
				if (!(errmsg=msgin.validate(Message.TYPE_CLIENT)).equals(Message.OK)) {
						
				    // invalid message received 
					
			    	warning(INVALID_MSG + " : "+ errmsg);
			    	send(oos, new Message(Message.MSG_INVALID_MSG, (String)(params.get(PARAM_TOKEN))));					    	
					
			    	continue;
				}
								    
				// valid message received 

				if (!error_severe.equals("")) {
						
					// applet needs to send it encountered an internal error
					// instead of processing the request.
						
				   	send(oos, new Message(Message.MSG_APPLET_ERROR, (String)(params.get(PARAM_TOKEN)), error_severe));
				    	
					error_severe = "";
				    
					continue;
				}
					
				msg_id = msgin.getType();
				
				// get SQL Server connection if DB request from Proxy
				
				if (msg_id.startsWith("SQL")) {
					if (!connectDatabase().equals("")) {						 							    		
					    msgout = new Message(Message.MSG_ODBC_ERROR, (String)(params.get(PARAM_TOKEN)), error_severe);							    						    
					    send(oos, msgout);
						error_severe = "";
						continue;
					}
				}
				
				if (msg_id.equals(Message.MSG_SQL_SELECT)) {				        
										    	
				    // SELECT
					
				    try {
					    start_rec = Integer.parseInt(msgin.getParam(0));
					    max_recs = Integer.parseInt(msgin.getParam(1));
						    	
					    //if (!current_sql.query.equals(msgin.getBody())) {
						    		
					        // new select
						    	
					    	tot_nr_rec = 0;
						    	
					        current_sql.setQuery(msgin.getBody());
					        flds = current_sql.getFields();					
						    rs = stmt.executeQuery(current_sql.query);						       
						    rs.last();
						    tot_nr_rec = rs.getRow();
					        info("found " + tot_nr_rec + " matching records");
					        rs.first(); // TODO : remove (1st test !!)
					    //}					    	
							
						if (tot_nr_rec == 0) {
							        
							// no records in the resultset 

						    msgout = new Message(Message.MSG_SQL_SEL_RES, (String)(params.get(PARAM_TOKEN)));
						    msgout.setParam(new String [] {"0","0"});
						    send(oos, msgout);
	                        
						    continue;   
						}
						
						// several records to send 
							    	
						if ((start_rec > tot_nr_rec) || (start_rec == 0)) {
							    	    
						    // invalid record requested 	
							    		
							send(oos, new Message(Message.MSG_SQL_ERROR, (String)(params.get(PARAM_TOKEN)), "invalid record requested"));							    	
                            
							continue;
						}
												    		
				        rs.absolute(start_rec);
				        
				        // send the SQL_SELECT_RESULT 
 					    		
						if (tot_nr_rec > max_recs) {
						    nb_recs = max_recs;
						} else {
						    nb_recs = tot_nr_rec;
						}
							        	
						for (int i=0; i < nb_recs; i++) {				
						
							msgout =  new Message(Message.MSG_SQL_SEL_RES, (String)(params.get(PARAM_TOKEN)));
							
							/* set parameters */
							String p[] = new String[2];
							p[0] = new Integer(i+1).toString();         // record nr (start from 1)
							p[1] = new Integer(tot_nr_rec).toString();  // total nr records returned by SQL Select
							msgout.setParam(p);
							
							msgout.setNbNext(nb_recs-i-1);              // nb of messages after this message							        		
							rec = new com.oasys.applet.commons.DbTable(flds);
							rec.setValues(rs);							             
							msgout.setRecord(rec);							        	
							send(oos, msgout);								        
							if (!rs.next()) break;
						}					
					} catch (SQLException e) {
						e.printStackTrace();
					    severe("SQL exception: " + e.getMessage()); 		
					    if (pw != null) e.printStackTrace(pw);
					    msgout = new Message(Message.MSG_SQL_ERROR, (String)(params.get(PARAM_TOKEN)), e.getMessage());							    						    
					    send(oos, msgout);
					   }
					
					continue;
					
				  }
				  
	    	      if (msg_id.equals(Message.MSG_SQL_INSERT) ||
					  msg_id.equals(Message.MSG_SQL_UPDATE) ||
					  msg_id.equals(Message.MSG_SQL_DELETE) ||
					  msg_id.equals(Message.MSG_SQL_CREATE) ||
					  msg_id.equals(Message.MSG_SQL_COMMIT) ||
					  msg_id.equals(Message.MSG_SQL_RBACK)  ||
					  msg_id.equals(Message.MSG_SQL_BEGIN)  ||
					  msg_id.equals(Message.MSG_SQL_DROP)) {
					    	     
				      // clear cache if INSERT, UPDATE or DELETE 
					    		 
					  if ( msg_id.equals(Message.MSG_SQL_INSERT) ||  
					       msg_id.equals(Message.MSG_SQL_UPDATE) ||
					       msg_id.equals(Message.MSG_SQL_DELETE)) {
					    	    	 					    	    	 
					       current_sql.setQuery("");
					   }
					    	     
					   // execute the DB statement 
					    	     
					   try {	   
					 	    stmt.executeUpdate(msgin.getBody());
					 		info(DB_OK);					 			
							msgout = new Message(Message.MSG_SQL_RES, (String)(params.get(PARAM_TOKEN)));							    	
							send(oos, msgout);
					 	} catch (SQLException e) {
					 	
					 	   	// statement failed 
					 	        
					 	   	severe("SQL exception : " + e.getMessage());
					 	   	if (pw != null) e.printStackTrace(pw); 
						    msgout = new Message(Message.MSG_SQL_ERROR, (String)(params.get(PARAM_TOKEN)), e.getMessage());							    	
						    send(oos, msgout);
							
					 	}
					    continue;
					}

		            if (msg_id.equals(Message.MSG_AUTH_OK)) {
					    		 
					    // not expecting an AUTH_OK 
					    		 
					    warning(ERR_AUTH_OK);
						msgout = new Message(Message.MSG_INVALID_MSG, (String)(params.get(PARAM_TOKEN)));							    	
						send(oos, msgout);						     
					}
		            else
		            if (msg_id.equals(Message.MSG_LOGOUT_REQ)) {
		            	//terminate(RC_OK,"","");		            	
		            }
		            else
		            // Reception of KEEP_ALIVE
		            // close the socket if another session replaced current
	            	// (in case of timeout on JBoss followed by user logon)
		            if (msg_id.equals(Message.MSG_KEEP_ALIVE)) { 
		            	if (!ssid.equals(params.get(PARAM_TOKEN))) {
		            		info("Closing " + socket.toString() + " for session " + params.get(PARAM_TOKEN));
		            		socket.close();
		            		return;
		            	}
		            }
		            
		    }
		}
		catch (Exception e) {
			try {
			    if (pw != null) e.printStackTrace(pw);
			    terminate(RC_ERROR, "Communication error", CALL_MENSURA);
	            String error = "Exception in start() method : " + e.getMessage();
	            severe(error);
		        int delay = getDelay();
			    info("Sleeping " + delay + "s before reconnect");			
			    Thread.sleep(delay * 1000);
			    start();
			    }
			    catch (Exception ex) {
			   	    start();
			    }				   
		    }	
	    }
    }
    
    /**
     * Retrieve the following parameters values sent in the HTML page and save
     * them in the HashMap.
     * 
     * <br>host - the host applet will connect (mandatory)
     * <br>port - the port the applet will connect (mandatory)
     * <br>token - the session id (mandatory)
     * <br>cert - server certificate (mandatory if ssl = yes)
     * <br>ssl - switch indicating if SSL is required (optional, default=yes)
     * <br>log_console - switch indicating if applet must output on console (optional, default=yes)
     * <br>log_file - switch indicating if applet must output to file (optional, default=no)
     */
    private void getServerParams() {
    	getServerMandatoryParam(PARAM_HOST);
    	getServerMandatoryParam(PARAM_PORT);
    	getServerMandatoryParam(PARAM_TOKEN);
        if (getServerOptionalParam(PARAM_SSL, YES).equals(YES)) {
        	getServerMandatoryParam(PARAM_CERT);	
        }
        getServerOptionalParam(PARAM_LOG_CONSOLE, YES);
        getServerOptionalParam(PARAM_LOG_FILE, NO);
    	
    }
    
    /**
     * Try to obtain the given mandatory parameter from the HTML page
     * and save it in the HashMap containing all parameters.
     * If the parameter is not obtained, terminate execution (sends the
     * error message to stdout because not logging is yet active !)
     * 
     * @param param the parameter wanted
     * @return parameter's value
     */
    private String getServerMandatoryParam(String param) {
    	
    	String value = getParameter(param);
    	
    	if ((value == null) || (value.equals(""))){
    		System.out.println("Applet can't start : missing or empty parameter " + param);
    		terminate(RC_ERROR, "", "Applet can't start : missing or empty parameter " + param);
    	} else {
    		params.put(param, value);
    	}
    	return value;
    	
    }
    	
	/**
	 * Try to obtain the given optional parameter from the HTML page
     * and save it in the HashMap containing all parameters.
     * 
	 * @param param  the optional parameter to obtain
	 * @param def    default value
	 * @return       parameter's value (default or value found)
	 */
    private String getServerOptionalParam(String param, String def) {
    	
		String value;
    	
    	if ((value = getParameter(param)) == null) {
    		value = def;	
    	}
    	params.put(param, value);	
    	return value;
	}
    
    
    /**
     * Send given Message on ObjectOutputStream and log
     * 
     * @param oos  ObjectOutputStream to use
     * @param msg  Message to send
     */
    private void send(ObjectOutputStream oos, Message msg) throws Exception {
        Messaging.send(oos, msg);
        info("sent: " + msg.toString());
    }
    private Message receive(ObjectInputStream ois) throws Exception {
	    Message msg = (Message)Messaging.receive(ois).get(0);					    
	    info("received: " + msg.toString());
	    return msg;
    }
	private void terminate(int rc, String logmsg, String dispmsg) {

        switch (rc) {
        
            case RC_OK: 
            	
    	        if (!logmsg.equals("")) info(logmsg);
    	        break;
    	        
            case RC_ERROR:
            	
            	if (!logmsg.equals("")) severe(logmsg);
            	if (!dispmsg.equals("")) {
            		MainWindow.call("displaymessage",
            				        new String [] {logmsg + " " + dispmsg});
            	}
            	break;
            	
        }
             
    }
	
	private void checkSize(String file, long maxsize) {
		try {
			File f = new File(file);
			if (f.length() >= maxsize) {
				f.delete();
				f.createNewFile();
			}				
		} catch (Exception e) {
			severe("Exception in checkSize (" + file + ") : " + e.getMessage());
		}
	}
	
    private void info(String msg) {
    	if (logger != null) logger.info(msg);
    }
    private void warning(String msg) {
    	if (logger != null) logger.warning(msg);
    }    
    private void severe(String msg) {
    	if (logger != null) logger.severe(msg);
    } 

    private String getWorkingDir() {
    	
    	File f1 = new File("c:\\mensura");
		File f2 = new File(System.getProperty("user.home"));
		File f3 = new File(System.getProperty("java.io.tmpdir"));
		
		if (f1.exists() && f1.canWrite()) 	return f1.getAbsolutePath();		
		if (f2.exists() && f2.canWrite())   return f2.getAbsolutePath();
		if (f3.exists() && f3.canWrite())   return f3.getAbsolutePath();
		
		return null;  		
    }
}

