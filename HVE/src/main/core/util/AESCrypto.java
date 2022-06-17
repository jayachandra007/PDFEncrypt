package main.core.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCrypto {
	private static final String ALGORITHM_AES = "AES";
	private static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5PADDING";
	private static final int AES_128 = 128;

	public SecretKey generateAESKey() throws NoSuchAlgorithmException {
		return generateAESKey(AES_128);
	}

	public SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
		keyGenerator.init(AES_128, new SecureRandom());
		return keyGenerator.generateKey();
	}

	public byte[] AESEncyprt(String plainText, SecretKey secretKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cipher = initialiseCipherForEncrypt(secretKey);
		return cipher.doFinal(plainText.getBytes());
	}

	public byte[] AESEncyprtFile(String pathToFile, String FileNameWithExt, SecretKey secretKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		String FileName = FileNameWithExt.substring(0, FileNameWithExt.lastIndexOf('.'));
		String FileExt = FileNameWithExt.substring(FileNameWithExt.lastIndexOf('.'));

		byte[] fileContentsInBytes = Files.readAllBytes(Paths.get(pathToFile + FileNameWithExt));

		Cipher cipher = initialiseCipherForEncrypt(secretKey);

		byte[] encBytes = cipher.doFinal(fileContentsInBytes);
		Files.write(Paths.get(pathToFile + FileName + "-enc" + FileExt), encBytes);

		return encBytes;
	}

	public byte[] AESDecyprtFile(String pathToFile, String FileNameWithExt, SecretKey secretKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		String FileName = FileNameWithExt.substring(0, FileNameWithExt.lastIndexOf('.'));
		String FileExt = FileNameWithExt.substring(FileNameWithExt.lastIndexOf('.'));

		byte[] fileContentsInBytes = Files.readAllBytes(Paths.get(pathToFile + FileNameWithExt));

		Cipher cipher = initialiseCipherForDecrypt(secretKey);

		byte[] decBytes = cipher.doFinal(fileContentsInBytes);
		Files.write(Paths.get(pathToFile + FileName + "-dec" + FileExt), decBytes);

		return decBytes;
	}

	private Cipher initialiseCipherForEncrypt(SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException {
		byte[] byteSecretKey = secretKey.getEncoded();
		SecretKeySpec skeySpec = new SecretKeySpec(byteSecretKey, ALGORITHM_AES);
		Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5PADDING);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));
		return cipher;
	}

	private Cipher initialiseCipherForDecrypt(SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException {
		byte[] byteSecretKey = secretKey.getEncoded();
		SecretKeySpec skeySpec = new SecretKeySpec(byteSecretKey, ALGORITHM_AES);
		Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5PADDING);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));
		return cipher;
	}
}
