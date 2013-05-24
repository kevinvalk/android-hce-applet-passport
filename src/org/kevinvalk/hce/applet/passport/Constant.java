package org.kevinvalk.hce.applet.passport;

public class Constant
{
    /* States */
    static final short STATE_LOCKED = 1;
    
	/* for authentication */
	static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;
	static final byte INS_GET_CHALLENGE = (byte) 0x84;
	static final byte CLA_PROTECTED_APDU = 0x0c;
	static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
	
	/* for EAC */
	static final byte INS_PSO = (byte) 0x2A;
	static final byte INS_MSE = (byte) 0x22;
	static final byte P2_VERIFYCERT = (byte) 0xBE;
	static final byte P1_SETFORCOMPUTATION = (byte) 0x41;
	static final byte P1_SETFORVERIFICATION = (byte) 0x81;
	static final byte P2_KAT = (byte) 0xA6;
	static final byte P2_DST = (byte) 0xB6;
	static final byte P2_AT = (byte) 0xA4;
	
	/* for reading */
	static final byte INS_SELECT_FILE = (byte) 0xA4;
	static final byte INS_READ_BINARY = (byte) 0xB0;
	
	/* for writing */
	static final byte INS_UPDATE_BINARY = (byte) 0xd6;
	static final byte INS_CREATE_FILE = (byte) 0xe0;
	static final byte INS_PUT_DATA = (byte) 0xda;
	static final short KEY_LENGTH = 16;
	static final short KEYMATERIAL_LENGTH = 16;
	static final short RND_LENGTH = 8;
	static final short MAC_LENGTH = 8;
	static final byte PRIVMODULUS_TAG = 0x60;
	static final byte PRIVEXPONENT_TAG = 0x61;
	static final byte MRZ_TAG = 0x62;
	static final byte ECPRIVATEKEY_TAG = 0x63;
	static final byte CVCERTIFICATE_TAG = 0x64;
	
	/* status words */
	static final short SW_OK = (short) 0x9000;
	static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
	static final short SW_INTERNAL_ERROR = (short) 0x6d66;
}
