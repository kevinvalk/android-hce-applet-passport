package org.kevinvalk.hce.applet.passport;

public class Passport
{
	String documentNo;
	String dateOfBirth;
	String dateOfExpiry;

	
	public Passport(String documentNo, String dateOfBirth, String dateOfExpiry)
	{
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
}
