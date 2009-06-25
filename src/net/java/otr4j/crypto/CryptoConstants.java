package net.java.otr4j.crypto;

import java.math.BigInteger;

public interface CryptoConstants {
	public static String MODULUS_TEXT = "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
	public static BigInteger MODULUS = new BigInteger(MODULUS_TEXT, 16);
	public static BigInteger BIGINTEGER_TWO = BigInteger.valueOf(2);
	public static BigInteger MODULUS_MINUS_TWO = MODULUS.subtract(BIGINTEGER_TWO);

	public static String GENERATOR_TEXT = "2";
	public static BigInteger GENERATOR = new BigInteger(GENERATOR_TEXT, 10);

	public static final int AES_KEY_BYTE_LENGTH = 16;
	public static final int SHA256_HMAC_KEY_BYTE_LENGTH = 32;
	public static final int DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH = 320;
	public static byte[] ZERO_CTR = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	public static int DSA_PUB_TYPE = 0;

	public static byte SSID_START = (byte) 0x00;
	public static byte C_START = (byte) 0x01;
	public static byte M1_START = (byte) 0x02;
	public static byte M2_START = (byte) 0x03;
	public static byte M1p_START = (byte) 0x04;
	public static byte M2p_START = (byte) 0x05;
	public static byte HIGH_SEND_BYTE = (byte)0x01;
	public static byte HIGH_RECEIVE_BYTE = (byte)0x02;
	public static byte LOW_SEND_BYTE = (byte)0x02;
	public static byte LOW_RECEIVE_BYTE = (byte)0x01;
	
	public static int SSID_LENGTH = 8;
	
	
}