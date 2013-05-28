package org.kevinvalk.hce.applet.passport.apdu;

import javax.crypto.SecretKey;

import org.kevinvalk.hce.applet.passport.Constant;
import org.kevinvalk.hce.applet.passport.Crypto;
import org.kevinvalk.hce.applet.passport.apdu.structure.MutualAuthenticateStructure;
import org.kevinvalk.hce.framework.Apdu;
import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;
import org.kevinvalk.hce.framework.apdu.BaseApdu;

import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;


@StructClass
public class MutualAuthenticateApdu extends BaseApdu
{
	@StructField(order = 0)
	public byte cla;
	
	@StructField(order = 1)
	public byte ins;
	
	@StructField(order = 2)
	public byte p1;
	
	@StructField(order = 3)
	public byte p2;
	
	@StructField(order = 4)
	public byte lc;
	
	@StructField(order = 5)
	public MutualAuthenticateStructure cdata = new MutualAuthenticateStructure();
	
	@StructField(order = 6)
	public byte[] mac = new byte[Constant.MAC_LENGTH];
	
	@StructField(order = 7)
	public byte le;
			
	public MutualAuthenticateApdu(SecretKey encKey, SecretKey macKey)
	{
		this.encKey = encKey;
		this.macKey = macKey;
	}

	@Override
	public int expectedLc()
	{
		return (Constant.RND_LENGTH + Constant.RND_LENGTH + Constant.KEYMATERIAL_LENGTH) + Constant.MAC_LENGTH;
	}
	
	@Override
	public Apdu toApdu()
	{
		Apdu apdu = null;
		try
		{
			// Encrypt
			byte[] cipher = Crypto.encrypt(JavaStruct.pack(cdata), encKey);
			JavaStruct.unpack(cdata, cipher);	
			
			// Calculate MAC
			mac = Crypto.getMac(cipher, macKey);
			
			// Return it
			apdu = new Apdu(JavaStruct.pack(this));
		}
		catch (StructException e)
		{
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
		return apdu;
	}

	public static MutualAuthenticateApdu fromApdu(Apdu apdu_, SecretKey encKey, SecretKey macKey)
	{
		// Save the keys	
		MutualAuthenticateApdu apdu = new MutualAuthenticateApdu(encKey, macKey);
		try
		{
			JavaStruct.unpack(apdu, apdu_.getBuffer());
			
			// Check MAC
			apdu.isVerified = Crypto.verifyMac(apdu.mac, Crypto.getMac(JavaStruct.pack(apdu.cdata), apdu.macKey));
			
			// If MAC was good decrypt it
			if (apdu.isVerified)
				JavaStruct.unpack(apdu.cdata, Crypto.decrypt(JavaStruct.pack(apdu.cdata), apdu.encKey));			
			
			return apdu;
		}
		catch (StructException e)
		{
			throw new RuntimeException(e.getMessage());
		}
	}

	@Override
	public boolean isVerified()
	{
		return isVerified;
	}
}
