package org.kevinvalk.hce.applet.passport;

import org.kevinvalk.hce.framework.Apdu;
import org.kevinvalk.hce.framework.Applet;
import org.kevinvalk.hce.framework.Iso7816;

public class PassportApplet extends Applet
{
	private Passport passport;
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
		Apdu apdu = sendApdu(new Apdu(Iso7816.SW_NO_ERROR));
		
		// Lets start handling all incomming traffic
		do
		{
			try
			{
				handleApdu(apdu);
			}
			catch(Exception e)
			{
				
			}
			
			
		}
		while(isRunning && apdu != null);
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean handleApdu(Apdu apdu) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public byte[] getAid()
	{
		return APPLET_AID;
	}

}
