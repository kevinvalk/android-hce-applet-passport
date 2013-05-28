package org.kevinvalk.hce.applet.passport.structure;

import org.kevinvalk.hce.framework.Iso7816;
import org.kevinvalk.hce.framework.IsoException;

import struct.JavaStruct;
import struct.StructException;

public abstract class Structure
{
	public byte[] getBuffer()
	{
		byte[] bytes = null;
		try
		{
			bytes = JavaStruct.pack(this);
		}
		catch (StructException e)
		{
			IsoException.throwIt(Iso7816.SW_INTERNAL_ERROR);
		}
		return bytes;
	}
}
