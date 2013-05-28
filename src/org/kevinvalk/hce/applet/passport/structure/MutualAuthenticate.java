package org.kevinvalk.hce.applet.passport.structure;

import org.kevinvalk.hce.applet.passport.Constant;
import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;

import struct.JavaStruct;
import struct.StructClass;
import struct.StructException;
import struct.StructField;

/**
 * Warning when the random fields can be the other way around
 * The first field is always from the send of this packet 
 *
 * If this APDU is from Terminal (ifd)
 * <p><code>randomFrom = RND.IFD<br>
 * randomTo = RND.ICC<br>
 * key = K.IFD</code></p>
 * 
 * If this APDU is from Card (icc)<br>
 * <p><code>randomFrom = RND.ICC<br>
 * randomTo = RND.IFD <br>
 * key = K.ICC</code></p>
 */
@StructClass
public class MutualAuthenticate extends Structure
{
	@StructField(order = 0)
	public byte[] randomFrom = new byte[Constant.RND_LENGTH];
	
	@StructField(order = 1)
	public byte[] randomTo = new byte[Constant.RND_LENGTH];
	
	@StructField(order = 2)
	public byte[] key = new byte[Constant.KEY_LENGTH];
	
	public MutualAuthenticate()
	{
		
	}
	
	public MutualAuthenticate(byte[] data)
	{
		try
		{
			JavaStruct.unpack(this, data);
		}
		catch (StructException e)
		{
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
	}
}
