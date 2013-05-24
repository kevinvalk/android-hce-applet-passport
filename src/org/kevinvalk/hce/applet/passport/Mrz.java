package org.kevinvalk.hce.applet.passport;

import java.io.UnsupportedEncodingException;

public class Mrz
{
	/**
	 * Casts a byte to the corresponding MRZ digit
	 * 
	 * @param ch
	 * @return
	 * @throws NumberFormatException
	 */
	private static int toMrzDigit(byte ch) throws NumberFormatException
	{
		switch (ch)
		{
			case '<': case '0': return 0; case '1': return 1; case '2': return 2; case '3': return 3; case '4': return 4;
			case '5': return 5;	case '6': return 6; case '7': return 7; case '8': return 8; case '9': return 9;
			case 'a': case 'A': return 10; case 'b': case 'B': return 11; case 'c': case 'C': return 12; case 'd': case 'D': return 13;
			case 'e': case 'E': return 14; case 'f': case 'F': return 15; case 'g': case 'G': return 16; case 'h': case 'H': return 17;
			case 'i': case 'I': return 18; case 'j': case 'J': return 19; case 'k': case 'K': return 20; case 'l': case 'L': return 21;
			case 'm': case 'M': return 22; case 'n': case 'N': return 23; case 'o': case 'O': return 24; case 'p': case 'P': return 25;
			case 'q': case 'Q': return 26; case 'r': case 'R': return 27; case 's': case 'S': return 28; case 't': case 'T': return 29;
			case 'u': case 'U': return 30; case 'v': case 'V': return 31; case 'w': case 'W': return 32; case 'x': case 'X': return 33;
			case 'y': case 'Y': return 34; case 'z': case 'Z': return 35;
			default:
				throw new NumberFormatException(String.format("Could not decode MRZ character %02X (%s)", ch, Character.toString((char)ch)));
		}
	}
	
	
	/**
	 * Computes the 7-3-1 check digit for part of the MRZ.
	 *
	 * @param str a part of the MRZ.
	 *
	 * @return the resulting check digit (in '0' - '9')
	 */
	public static char checkDigit(String str)
	{
		return checkDigit(str, false);
	}
	
	/**
	 * Computes the 7-3-1 check digit for part of the MRZ.
	 * If <code>preferFillerOverZero</code> is <code>true</code> then '<' will be
	 * returned on check digit 0.
	 *
	 * @param str a part of the MRZ.
	 *
	 * @return the resulting check digit (in '0' - '9', '<')
	 */
	private static char checkDigit(String str, boolean preferFillerOverZero) {
		try {
			byte[] chars = str == null ? new byte[]{ } : str.getBytes("UTF-8");
			int[] weights = { 7, 3, 1 };
			int result = 0;
			for (int i = 0; i < chars.length; i++) {
				result = (result + weights[i % 3] * toMrzDigit(chars[i])) % 10;
			}
			String checkDigitString = Integer.toString(result);
			if (checkDigitString.length() != 1) { throw new IllegalStateException("Error in computing check digit."); /* NOTE: Never happens. */ }
			char checkDigit = (char)checkDigitString.getBytes("UTF-8")[0];
			if (preferFillerOverZero && checkDigit == '0') { checkDigit = '<'; }
			return checkDigit;
		} catch (NumberFormatException nfe) {
			/* NOTE: never happens. */
			nfe.printStackTrace();
			throw new IllegalStateException("Error in computing check digit.");
		} catch (UnsupportedEncodingException usee) {
			/* NOTE: never happens. */
			usee.printStackTrace();
			throw new IllegalStateException("Error in computing check digit.");
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalArgumentException(e.toString());
		}
	}
}
