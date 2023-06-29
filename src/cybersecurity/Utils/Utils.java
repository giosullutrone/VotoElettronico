package cybersecurity.Utils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Utils
{
    //Define the character rapresenting the hexadeciamal numeration
    private static String digits = "0123456789abcdef";

    /**
     * Given an array of data returns it's rappresentation as 
     * an hexadecimal number
     * 
     * @param data
     * @param length lenght of the given data array
     * @return String
     */
    public static String toHex(byte[] data, int length){
        StringBuffer buf = new StringBuffer();
        //Iterate on the given lenght
        for (int i = 0; i != length; i++){
            //Taking the lesat significant value
            int v = data[i] & 0xff;
            //Realy dunno the following bitwise operations
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    /**
     * Given an array of data returns it's rappresentation as 
     * an hexadecimal number
     * 
     * @param data
     * @return String
     */
    public static String toHex(byte[] data){
	    return toHex(data, data.length);
	}

    /**
     * Create a Key for the AES encryption of the given bitLength
     * 
     * @param bitLength
     * @param random
     * @return AESKey
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(int bitLength, SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(bitLength, random);
        return generator.generateKey();
    }

    /**
     * Create a key for the AES encryption of 128 bit
     * 
     * @param random
     * @return AESkey
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128, random);
        return generator.generateKey();
    }

    /**
     * Create an inizalization vector for the AES algotrithm
     * 
     * 
     * @param random
     * @return
     */
    public static IvParameterSpec createCtrIvForAES(SecureRandom random){
        byte[] ivBytes = new byte[16];
        // initially randomize
        random.nextBytes(ivBytes);
        // set the counter bytes to 0
        for (int i = 0; i != 8; i++){
            ivBytes[8 + i] = 0;
        }
        return new IvParameterSpec(ivBytes);
    }

    /**
     * Given a byte array returns the rappresentation as a String 
     * 
     * @param bytes
     * @param length dimension of the given byte array
     * @return
     */
    public static String toString(byte[] bytes, int length){
        char[]	chars = new char[length];
        //iterate on the chars dimension
        for (int i = 0; i != chars.length; i++){
            //take the less significat value every time
            chars[i] = (char)(bytes[i] & 0xff);
        }
        return new String(chars);
    }

    /**
     * Given a byte array returns  part of the rappresentation as a String 
     * starting from the index from
     * 
     * @param bytes
     * @param from
     * @param length
     * @return
     */
    public static String toString(byte[] bytes, int from, int length){
        char[]	chars = new char[length];
        //iterate on the chars dimension
        for (int i = from; i != chars.length; i++){
            //take the less significat value every time
            chars[i] = (char)(bytes[i] & 0xff);
        }
        return new String(chars);
    }

    /**
     * Given a byte array returns the rappresentation as a String 
     * 
     * @param bytes
     * @return
     */
    public static String toString(byte[]	bytes){
        return toString(bytes, bytes.length);
    }

    /**
     * Given a string create it's rappresentation as a byte array
     * 
     * @param string
     * @return
     */
    public static byte[] toByteArray(String string){
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        for (int i = 0; i != chars.length; i++){
            bytes[i] = (byte)chars[i];
        }
        return bytes;
    }
    
    public static byte[] concatByteArrays(byte[] first, byte[] second) {        
        byte[] randConcat = new byte[first.length + second.length];
        System.arraycopy(first, 0, randConcat, 0, first.length);
        System.arraycopy(second, 0, randConcat, first.length, second.length);
        return randConcat;
    }
    
    public static byte[] stringToBytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
    
    public static String bytesToString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
    
    public static String toString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    public static String toString(KeyPair keyPair) {
        return toString(keyPair.getPublic()) + "," + toString(keyPair.getPrivate());
    }
}