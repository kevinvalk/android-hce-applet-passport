package org.kevinvalk.hce.applet.passport;

import org.kevinvalk.hce.applet.passport.apdu.*;
import org.kevinvalk.hce.framework.Apdu;
import org.kevinvalk.hce.framework.Applet;
import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;

public class PassportApplet extends Applet
{
	private Passport passport;
	private static final String APPLET_NAME = "e-passport";
	private static final byte[] APPLET_AID = { (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

	public PassportApplet(Passport passport)
	{
		this.passport = passport;
	}
	
	@Override
	public void run()
	{
		// We are running and we can send we are OK
		isRunning = true;
		
		// Lets start handling all incomming traffic
		do
		{
			try
			{		
				Apdu response = handleApdu(apdu);
				
				// Check if we have response left
				if (response != null)
				{
					apdu = sendApdu(response);
				}
				else
				{
					// TODO: Keep alive
					isRunning = false;
				}
			}
			catch(IsoException iso)
			{
				// We got an soft error so send response to our terminal
				apdu = sendApdu(new Apdu(iso.getErrorCode()));
			}
			catch(Exception e)
			{
				isRunning = false;
				d("Caught a real bad exception");
			}
		}
		while(isRunning && apdu != null);
		d("Stopping");
	}

	@Override
	public Apdu handleApdu(Apdu apdu)
	{
		Apdu response = null;
        switch(apdu.header.ins)
        {
        	case Constant.INS_SELECT_FILE:
        		response = apduSelectFile(apdu);
        	break;
        	case Constant.INS_GET_CHALLENGE:
        		response = apduGetChallenge(apdu);
        	break;
        	case Constant.INS_EXTERNAL_AUTHENTICATE:
                //response = apduExternalAuthenticate(cla, ins, p1, p2, lc, le, protectedApdu, buffer);
        	break;
        }
		return response;
	}
	
	/*** Apdu handlers ***/
	private Apdu apduSelectFile(Apdu apdu)
	{
		if (passport.isLocked() || ! passport.hasMutuallyAuthenticated())
            IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		if (apdu.getLc() != 2)
			IsoException.throwIt(Iso7816.SW_WRONG_LENGTH);

		// Get the file id
		short fid = apdu.getShort(Iso7816.OFFSET_CDATA);
		d("Selecting file %d", fid);
		
		// TODO: Implement file system
		IsoException.throwIt(Iso7816.SW_FILE_NOT_FOUND);
		
		return null;
	}
	
	/**
	 * Only supports BAC
	 * @param apdu
	 * @return
	 */
	private Apdu apduGetChallenge(Apdu apdu)
	{
		if ( ! passport.hasMutualAuthenticationKeys() || passport.hasMutuallyAuthenticated())
			IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
	    if (apdu.getLc() != 8)
	    	IsoException.throwIt(Iso7816.SW_WRONG_LENGTH);
	    
	    ChallengeApdu challenge = new ChallengeApdu();
	    challenge.rnd = new byte[] { 0x46, 0x08, (byte) 0xF9, 0x19, (byte) 0x88, 0x70, 0x22, 0x12 };
	    
	    passport.state |= Constant.STATE_CHALLENGED;
	    return challenge.toApdu();
	}
	
	@Override
	public String getName()
	{
		return APPLET_NAME;
	}

	@Override
	public byte[] getAid()
	{
		return APPLET_AID;
	}

}
