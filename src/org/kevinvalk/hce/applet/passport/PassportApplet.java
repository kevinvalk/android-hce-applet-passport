package org.kevinvalk.hce.applet.passport;

import java.util.Arrays;

import org.kevinvalk.hce.applet.passport.structure.*;
import org.kevinvalk.hce.framework.apdu.*;
import org.kevinvalk.hce.framework.Applet;
import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;
import org.kevinvalk.hce.framework.Util;

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
	public void select()
	{
		d("Resetting the passport");
		passport.reset();
	}
	
	@Override
	public ResponseApdu process(CommandApdu apdu) throws IsoException
	{
		// Firstly check if it is protected and if so unwrap it
		boolean isProtected = (apdu.cla & Constant.CLA_PROTECTED_APDU) == Constant.CLA_PROTECTED_APDU;
		if (isProtected)
		{
			apdu = SecureApdu.unwrapCommandApdu(apdu);
		}
		
		ResponseApdu response = null;
        switch(apdu.ins)
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
        	default:
        		response = new ResponseApdu(Iso7816.SW_INS_NOT_SUPPORTED);
        	break;
        }
		return response;
	}
	
	/*** Apdu handlers ***/
	private ResponseApdu apduSelectFile(CommandApdu apdu)
	{
		if (passport.isLocked() || ! passport.hasMutuallyAuthenticated())
            IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		if (apdu.getLc() != 2)
			IsoException.throwIt(Iso7816.SW_WRONG_LENGTH);
		
		// TODO: Implement file system
		IsoException.throwIt(Iso7816.SW_FILE_NOT_FOUND);
		
		return null;
	}
	
	/**
	 * Only supports BAC
	 * @param apdu
	 * @return
	 */
	private ResponseApdu apduGetChallenge(CommandApdu apdu)
	{
		// Security state check
		if ( ! passport.hasMutualAuthenticationKeys() || passport.hasMutuallyAuthenticated())
			IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		// Check if the expected length is correct
	    if (apdu.getLe() != Constant.RND_LENGTH)
	    	IsoException.throwIt(Iso7816.SW_WRONG_LENGTH);
	    
	    passport.sessionRandom = new byte[] { 0x46, 0x08, (byte) 0xF9, 0x19, (byte) 0x88, 0x70, 0x22, 0x12 };
	    
	    passport.state |= Constant.STATE_CHALLENGED;
	    return new ResponseApdu(passport.sessionRandom, Iso7816.SW_NO_ERROR);
	}
	
	private ResponseApdu apduMutualAuthenticate(CommandApdu apdu)
	{
		// Security state check
		if ( ! passport.isChallenged() || passport.hasMutuallyAuthenticated())
			IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		// Check if the length is correct
		if (apdu.getLc() != Constant.LC_MUTUAL_AUTHENTICATE_TOTAL)
			IsoException.throwIt(Iso7816.SW_WRONG_LENGTH);
		
        // Extract the mac and the cipher from the apdu
        byte[] cipher = Arrays.copyOfRange(apdu.getData(), 0, Constant.LC_MUTUAL_AUTHENTICATE_DATA);
        byte[] mac = Arrays.copyOfRange(apdu.getData(), Constant.LC_MUTUAL_AUTHENTICATE_DATA, Constant.LC_MUTUAL_AUTHENTICATE_TOTAL);

        // Step (a) verify by MAC[K_MAC](EIFD) == MIFD
        if ( ! Crypto.verifyMac(mac, Crypto.getMac(cipher, passport.mutualMacKey)))
        	IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        
        // Step (b) decrypt EIFD by D[K_ENC](EIFD) = PIFD
        MutualAuthenticate data = new MutualAuthenticate(cipher, passport.mutualEncKey);
                
        // Step (c) check if the random I (icc) send is the same as the terminal (ifd) send back
        if ( ! Arrays.equals(passport.sessionRandom, data.randomTo))
        	IsoException.throwIt(Iso7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        
        // Step (d) generate keying material K.ICC
        //byte[] kIcc = Util.getRandom(KEYMATERIAL_LENGTH);
        passport.sessionKeySeed = new byte[] { 0x0B, 0x4F, (byte) 0x80, 0x32, 0x3E, (byte) 0xB3, 0x19, 0x1C, (byte) 0xB0, 0x49, 0x70, (byte) 0xCB, 0x40, 0x52, 0x79, 0x0B };
        
        // Step (e) generate the R = RND.ICC || RND.IFD || K.ICC
        MutualAuthenticate response = new MutualAuthenticate();
        response.randomFrom = passport.sessionRandom;
        response.randomTo = data.randomFrom;
        response.key = passport.sessionKeySeed;
        
        // Calculate the session information
        passport.sessionKeySeed = Util.xorArray(data.key, response.key);
        passport.sessionEncKey = Crypto.deriveKey(passport.sessionKeySeed, Crypto.ENC_MODE);
        passport.sessionMacKey = Crypto.deriveKey(passport.sessionKeySeed, Crypto.MAC_MODE);
        passport.ssc = Util.getSomething(passport.sessionRandom, 4, 4) << 32 | Util.getSomething(data.randomFrom, 4, 4);
        
		d("KEYSEED: %s\nRND.IFD: %s\nRND.ICC: %s\nK.IFD: %s\nK.ICC: %s\nKseed: %s\nSSC: %s\n",
			Util.toHex(passport.mutualKeySeed),
			Util.toHex(data.randomFrom),
			Util.toHex(passport.sessionRandom),
			Util.toHex(data.key),
			Util.toHex(response.key),
			Util.toHex(passport.sessionKeySeed),
			Util.toHex(Util.toBytes(passport.ssc))
		);
				
        // Step (f, g, h) send the cryptogram and mac back
        return new ResponseApdu(response.getEncoded(passport.mutualMacKey, passport.mutualEncKey), Iso7816.SW_NO_ERROR);
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
