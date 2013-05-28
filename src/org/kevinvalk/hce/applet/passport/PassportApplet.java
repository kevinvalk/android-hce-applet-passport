package org.kevinvalk.hce.applet.passport;

import java.util.Arrays;

import org.kevinvalk.hce.applet.passport.apdu.*;
import org.kevinvalk.hce.applet.passport.apdu.structure.*;
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
        	case Constant.INS_MUTUAL_AUTHENTICATE:
                response = apduMutualAuthenticate(apdu);
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
		
	    if (apdu.getLc() != 8) // In reality this is actually the Le field
	    	IsoException.throwIt(Iso7816.SW_WRONG_LENGTH);
	    
	    passport.sessionRandom = new byte[] { 0x46, 0x08, (byte) 0xF9, 0x19, (byte) 0x88, 0x70, 0x22, 0x12 };
	    ChallengeApdu challenge = new ChallengeApdu();
	    challenge.rnd = passport.sessionRandom;
	    
	    passport.state |= Constant.STATE_CHALLENGED;
	    return challenge.toApdu();
	}
	
	private Apdu apduMutualAuthenticate(Apdu apdu_)
	{
		if ( ! passport.isChallenged() || passport.hasMutuallyAuthenticated())
			IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		MutualAuthenticateApdu apdu = MutualAuthenticateApdu.fromApdu(apdu_, passport.mutualEncKey, passport.mutualMacKey);
		
		// Check if its correct length
		if (apdu.lc != apdu.expectedLc())
			IsoException.throwIt(Iso7816.SW_WRONG_LENGTH);
			
        // Step (a) verify by MAC[K_MAC](EIFD) == MIFD
        if ( ! apdu.isVerified())
        	IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                
        // Step (c) check if the random I (icc) send is the same as the terminal (ifd) send back
        if ( ! Arrays.equals(passport.sessionRandom, apdu.cdata.randomTo))
        	IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        
        // Step (d) generate keying material K.ICC
        //byte[] kIcc = Util.getRandom(KEYMATERIAL_LENGTH);
        passport.sessionKey = new byte[] { 0x0B, 0x4F, (byte) 0x80, 0x32, 0x3E, (byte) 0xB3, 0x19, 0x1C, (byte) 0xB0, 0x49, 0x70, (byte) 0xCB, 0x40, 0x52, 0x79, 0x0B };
        
        // Step (e) generate the R = RND.ICC || RND.IFD || K.ICC
        MutualAuthenticateApdu response = new MutualAuthenticateApdu(passport.mutualEncKey, passport.mutualMacKey);
        response.cdata.randomFrom = passport.sessionRandom;
        response.cdata.randomTo = apdu.cdata.randomFrom;
        response.cdata.key = passport.sessionKey;
        
        return response.toApdu();
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
