package org.kevinvalk.hce.applet.passport;

public class Constant
{
    /* States */
	public static final short STATE_LOCKED = 1;
	public static final short STATE_CHALLENGED = 2;
    
	/* for authentication */
    public static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;
	public static final byte INS_GET_CHALLENGE = (byte) 0x84;
	public static final byte CLA_PROTECTED_APDU = 0x0c;
	public static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
	
	/* for EAC */
	public static final byte INS_PSO = (byte) 0x2A;
	public static final byte INS_MSE = (byte) 0x22;
	public static final byte P2_VERIFYCERT = (byte) 0xBE;
	public static final byte P1_SETFORCOMPUTATION = (byte) 0x41;
	public static final byte P1_SETFORVERIFICATION = (byte) 0x81;
	public static final byte P2_KAT = (byte) 0xA6;
	public static final byte P2_DST = (byte) 0xB6;
	public static final byte P2_AT = (byte) 0xA4;
	
	/* for reading */
	public static final byte INS_SELECT_FILE = (byte) 0xA4;
	public static final byte INS_READ_BINARY = (byte) 0xB0;
	
	/* for writing */
	public static final byte INS_UPDATE_BINARY = (byte) 0xd6;
	public static final byte INS_CREATE_FILE = (byte) 0xe0;
	public static final byte INS_PUT_DATA = (byte) 0xda;
	public static final short KEY_LENGTH = 16;
	public static final short KEYMATERIAL_LENGTH = 16;
	public static final short RND_LENGTH = 8;
	public static final short MAC_LENGTH = 8;
	public static final byte PRIVMODULUS_TAG = 0x60;
	public static final byte PRIVEXPONENT_TAG = 0x61;
	public static final byte MRZ_TAG = 0x62;
	public static final byte ECPRIVATEKEY_TAG = 0x63;
	public static final byte CVCERTIFICATE_TAG = 0x64;
}
