package org.kevinvalk.hce.applet.passport;

import javax.crypto.SecretKey;

import org.kevinvalk.hce.framework.Applet;

public class Passport
{
	// MRZ information
	private String documentNo;
	private String dateOfBirth;
	private String dateOfExpiry;
	
	// Key information
	public byte[] mutualKeySeed;
	public SecretKey mutualMacKey = null, mutualEncKey = null;
	public SecretKey macKey = null, encKey = null;

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
	
	public boolean calculateInitialKey()
	{
		// TODO: Calculate initial key based on doc, dob, doe
		mutualKeySeed = Crypto.computeKeySeed(documentNo, dateOfBirth, dateOfExpiry);
		mutualEncKey = Crypto.deriveKey(mutualKeySeed, Crypto.ENC_MODE);
		mutualMacKey = Crypto.deriveKey(mutualKeySeed, Crypto.MAC_MODE);

		Applet.sd("CRYPTO", "Keyseed: %s", Applet.toSHex(mutualKeySeed));
		Applet.sd("CRYPTO", "Kenc: %s", Applet.toSHex(mutualEncKey.getEncoded()));
		Applet.sd("CRYPTO", "Kmac: %s", Applet.toSHex(mutualMacKey.getEncoded()));
		
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
    	return (macKey != null && encKey != null);
    }
    
    public boolean hasMutualAuthenticationKeys()
    {
    	return (mutualMacKey != null && mutualEncKey != null);
    }
    
    public boolean isLocked()
    {
        return getState(Constant.STATE_LOCKED);
    }
    
    public boolean getState(int state)
    {
    	return (this.state & state) == state;
    }
}
