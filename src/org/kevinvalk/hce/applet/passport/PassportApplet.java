package org.kevinvalk.hce.applet.passport;

import org.kevinvalk.hce.framework.Apdu;
import org.kevinvalk.hce.framework.Applet;
import org.kevinvalk.hce.framework.Iso7816;

import android.util.Log;

public class PassportApplet extends Applet
{
	private Passport passport;
	private static final String APPLET_NAME = "e-passport";
	private static final byte[] APPLET_AID = { (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

	
	static public void d(String msg)
	{
		Log.d("EPASS", msg);
	}
	
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
					apdu = sendApdu(response);
				else
					isRunning = false;
			}
			catch(Exception e)
			{
			
				isRunning = false;
			}
		}
		while(isRunning && apdu != null);
		d("Stopping");
	}

	@Override
	public Apdu handleApdu(Apdu apdu)
	{
		d("Handle apdu");
		return null;
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
