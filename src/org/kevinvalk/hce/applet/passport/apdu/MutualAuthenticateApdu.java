package org.kevinvalk.hce.applet.passport.apdu;

import java.util.Arrays;

import javax.crypto.SecretKey;

import org.kevinvalk.hce.applet.passport.Constant;
import org.kevinvalk.hce.applet.passport.Crypto;
import org.kevinvalk.hce.applet.passport.apdu.structure.MutualAuthenticateStructure;
import org.kevinvalk.hce.framework.Apdu;

import struct.ArrayLengthMarker;
import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;


@StructClass
public class MutualAuthenticateApdu
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
	@ArrayLengthMarker(fieldName = "cdata")
	public byte lc;
	
	@StructField(order = 5)
	public byte[] cdata;
	
	@StructField(order = 6)
	public byte le;
	
	
	private MutualAuthenticateStructure dataStruct = null;
	public MutualAuthenticateStructure getData(SecretKey key)
	{
		if (dataStruct == null)
		{
			dataStruct = new MutualAuthenticateStructure();
			try
			{
				JavaStruct.unpack(dataStruct, Crypto.decrypt(getEncIfd(), key));
			}
			catch (StructException e)
			{
				throw new RuntimeException(e.getMessage());
			}
		}
			
		return dataStruct;
	}
	
	public byte[] getEncIfd()
	{
		return Arrays.copyOfRange(cdata, 0, lc-8);
	}
	
	public byte[] getMacIfd()
	{
		return Arrays.copyOfRange(cdata, 32, lc);
	}
		
	static final public int getIfdLength()
	{
		return Constant.RND_LENGTH + Constant.RND_LENGTH + Constant.KEYMATERIAL_LENGTH;
	}
	
	static public MutualAuthenticateApdu fromApdu(Apdu apdu)
	{
		MutualAuthenticateApdu mutualAuthenticateApdu = new MutualAuthenticateApdu();
		try
		{
			JavaStruct.unpack(mutualAuthenticateApdu, apdu.getBuffer());
			return mutualAuthenticateApdu;
		}
		catch (StructException e)
		{
			throw new RuntimeException(e.getMessage());
		}
	}
}
