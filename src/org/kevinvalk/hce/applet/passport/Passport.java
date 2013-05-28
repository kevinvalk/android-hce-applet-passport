package org.kevinvalk.hce.applet.passport;

import javax.crypto.SecretKey;

import org.kevinvalk.hce.framework.Util;

public class Passport
{
	// MRZ information
	private String documentNo;
	private String dateOfBirth;
	private String dateOfExpiry;
	
	// Mutual Key Information
	public byte[] mutualKeySeed;
	public SecretKey mutualMacKey = null, mutualEncKey = null;
	
	// Session Key Information
	public long ssc;
	public byte[] sessionRandom;
	public byte[] sessionKeySeed;
	public SecretKey sessionMacKey = null, sessionEncKey = null;


	// State information
	public int state;
	
	public Passport(String documentNo, String dateOfBirth, String dateOfExpiry)
	{
		// Set our initial state
		this.state = Constant.STATE_LOCKED;
		
		// Set MRZ and calculate initial key
		this.documentNo = documentNo;
		this.dateOfBirth = dateOfBirth;
		this.dateOfExpiry = dateOfExpiry;
		calculateInitialKey();
	}
	
	public void reset()
	{
		// Set the initial state
		state = Constant.STATE_LOCKED;
		
		// Reset the session
		ssc = 0;
		sessionRandom = null;
		sessionKeySeed = null;
		sessionEncKey = null;
		sessionMacKey = null;
	}
	
	public boolean calculateInitialKey()
	{
		mutualKeySeed = Crypto.computeKeySeed(documentNo, dateOfBirth, dateOfExpiry);
		mutualEncKey = Crypto.deriveKey(mutualKeySeed, Crypto.ENC_MODE);
		mutualMacKey = Crypto.deriveKey(mutualKeySeed, Crypto.MAC_MODE);

		Util.d("CRYPTO", "Keyseed: %s", Util.toUnspacedHex(mutualKeySeed));
		Util.d("CRYPTO", "Kenc: %s", Util.toUnspacedHex(mutualEncKey.getEncoded()));
		Util.d("CRYPTO", "Kmac: %s", Util.toUnspacedHex(mutualMacKey.getEncoded()));
		
		return true;
	}
	
	
	/*** Properties ***/
	public void setDocumentNumber(String documentNo)
	{
		this.documentNo = documentNo;
		calculateInitialKey();
	}
	
	public void setDateOfBirth(String dateOfBirth)
	{
		this.dateOfBirth = dateOfBirth;
		calculateInitialKey();
	}
	
	public void setDateOfExpiry(String dateOfExpiry)
	{
		this.dateOfExpiry = dateOfExpiry;
		calculateInitialKey();
	}
	
	/*** State properties ***/
    public boolean hasMutuallyAuthenticated()
    {
    	return (sessionMacKey != null && sessionEncKey != null);
    }
    
    public boolean hasMutualAuthenticationKeys()
    {
    	return (mutualMacKey != null && mutualEncKey != null);
    }
    
    public boolean isLocked()
    {
        return getState(Constant.STATE_LOCKED);
    }
    
    public boolean isChallenged()
    {
    	return getState(Constant.STATE_CHALLENGED);
    }
    
    public boolean getState(int state)
    {
    	return (this.state & state) == state;
    }
}
