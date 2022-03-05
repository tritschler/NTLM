package com.tritschler.ntlm;

/**
 * Buffer Management
 * 
 * @author <a href="mailto:marc.tritschler@c-w.be">marc.tritschler@c-w.be</a>
 *
 */
public class HexBuff {
	
    public static void dumpBuff(byte[] buff) {
    	String h = "";
    	String t = "";
    	int k = 1;
    	for (int i=0; i<buff.length; i++) {
    		t = Integer.toHexString(buff[i]);
    		if (t.length()==1)      h += "0" + t + " ";
    		else if (t.length()>2)  h += t.substring(6,8) + " ";    		
    		else                    h += t + " ";
    		if ((k%32)==0) h+="\n";
    		k++;
    	}
    	System.out.println(h);
    }
    
    public static byte [] getBytes(byte [] buff, int s, int e) {
    	byte [] out = new byte [e-s];
    	int k = 0;
    	//System.out.println("getBytes: input = " + buff.length + " bytes");
    	for (int i=0; i< buff.length; i++) {
    		if ((i>=s) && (i<=e))  {
    			out[k] = buff[i]; k++;
    		}  
    		if (k == 8) break;
    	}
    	//System.out.println("getBytes: out = " + out.length + " bytes");
    	return out;
    }
   
    
}

