package org.kevinvalk.hce.applet.passport.apdu;

import org.kevinvalk.hce.framework.Apdu;
import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;
import org.kevinvalk.hce.applet.passport.Constant;

import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;

@StructClass
public class ChallengeApdu
{
	@StructField(order = 0)
	public byte[] rnd = new byte[Constant.RND_LENGTH];
	
	@StructField(order = 1)
	public short state = Iso7816.SW_NO_ERROR;
	
	public Apdu toApdu() throws IsoException
	{
		try {
			return new Apdu(JavaStruct.pack(this));
		} catch (StructException e) {
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
		return null;
	}
}
