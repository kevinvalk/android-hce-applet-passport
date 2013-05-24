package org.kevinvalk.hce.applet.passport;

import javax.crypto.SecretKey;

public class Passport
{
	// MRZ information
	private String documentNo;
	private String dateOfBirth;
	private String dateOfExpiry;
	
	// Key information
	public byte[] initialKeySeed;
	public SecretKey initialMacKey, initialEncKey;
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
    
    public boolean isLocked()
    {
        return getState(Constant.STATE_LOCKED);
    }
    
    public boolean getState(int state)
    {
    	return (this.state & state) == state;
    }
}
