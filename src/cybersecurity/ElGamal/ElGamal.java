package cybersecurity.ElGamal;

import cybersecurity.Utils.Utils;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.util.Arrays;

public class ElGamal {
    private final SecureRandom random;
    private final Cipher cipher;
    public static final int SECURITYPARAMETER = 512;
    private static final int plainTextBlockLength = 32;
    private static final int cypherTextBlockLength = 128;
    
    public ElGamal() throws NoSuchAlgorithmException, NoSuchPaddingException {
        random = new SecureRandom();
        cipher = Cipher.getInstance("ElGamal/None/PKCS1Padding");
    }
    
    private byte[] encodeNotSafe(byte[] message, PublicKey PK) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {        
        cipher.init(Cipher.ENCRYPT_MODE, PK, random);
        return cipher.doFinal(message);
    }
    
    public byte[] encode(byte[] message, PublicKey PK) throws Exception {   
        if (message.length > plainTextBlockLength) {
            byte[] block, result = new byte[] {0};
            int i=0;
            
            while(i < message.length / plainTextBlockLength) {
                block = this.encodeNotSafe(Arrays.copyOfRange(message, i*plainTextBlockLength, (i+1)*plainTextBlockLength), PK);
                result = (i!=0) ? Utils.concatByteArrays(result, block) : block;
                i+=1;
            }
            if (message.length % plainTextBlockLength > 0) {
                block = this.encodeNotSafe(Arrays.copyOfRange(message, message.length - message.length % plainTextBlockLength, message.length), PK);
                result = (i!=0) ? Utils.concatByteArrays(result, block) : block;
            }
            
            return result;
        }
        return encodeNotSafe(message, PK);
    }
    
    private byte[] decodeNotSafe(byte[] message, PrivateKey SK) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, SK);
        return cipher.doFinal(message);
    }
    
    private int getOutputSizeOfBlockEnc(PublicKey PK) throws Exception{
        cipher.init(Cipher.ENCRYPT_MODE, PK);
        return cipher.getOutputSize(plainTextBlockLength);
    }
    
    public byte[] decode(byte[] message, PublicKey PK, PrivateKey SK) throws Exception {
        int l = getOutputSizeOfBlockEnc(PK);
        if (message.length > l) {
            byte[] block, result = new byte[] {0};
            int i=0;
            
            while(i*l < message.length) {
                block = this.decodeNotSafe(Arrays.copyOfRange(message, i*l, (i+1)*l), SK);
                result = (i!=0) ? Utils.concatByteArrays(result, block) : block;
                i+=1;
            }
            
            if (message.length % l > 0) {
                block = this.decodeNotSafe(Arrays.copyOfRange(message, message.length - message.length % l, message.length), SK);
                result = (i!=0) ? Utils.concatByteArrays(result, block) : block;
            }
            return result;
        }
        return decodeNotSafe(message, SK);
    }
    
    public byte[] decode(byte[] message, PrivateKey SK) throws Exception {        
        if (message.length > cypherTextBlockLength) {
            byte[] block, result = new byte[] {0};
            int i=0;
            
            while(i*cypherTextBlockLength < message.length) {
                block = this.decodeNotSafe(Arrays.copyOfRange(message, i*cypherTextBlockLength, (i+1)*cypherTextBlockLength), SK);
                result = (i!=0) ? Utils.concatByteArrays(result, block) : block;
                i+=1;
            }
            
            if (message.length % cypherTextBlockLength > 0) {
                block = this.decodeNotSafe(Arrays.copyOfRange(message, message.length - message.length % cypherTextBlockLength, message.length), SK);
                result = (i!=0) ? Utils.concatByteArrays(result, block) : block;
            }
            return result;
        }
        return decodeNotSafe(message, SK);
    }
    
    public KeyPairCustom generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal");
        generator.initialize(SECURITYPARAMETER, random);
        KeyPair keyPair = generator.generateKeyPair();
        
        PublicKeyCustom publicKeyCustom = new PublicKeyCustom(keyPair.getPublic(), 
                                                              ElGamal.getH(keyPair.getPublic(), keyPair.getPrivate()));
        return new KeyPairCustom(publicKeyCustom, keyPair.getPrivate());
    }

    public static PrivateKey convertPrivateKey(BigInteger y, BigInteger p, BigInteger g) throws Exception {
        ElGamalPrivateKeySpec SK;
        SK = new ElGamalPrivateKeySpec(y, new ElGamalParameterSpec(p, g));
        KeyFactory factory = KeyFactory.getInstance("ElGamal");
        return factory.generatePrivate(SK);
    }

    public static BigInteger getP(PublicKey key) {
        return ((DHPublicKey) key).getParams().getP();
    }

    public static BigInteger getP(PrivateKey key) {
        return ((DHPrivateKey) key).getParams().getP();
    }
    
    public static BigInteger getQ(PublicKey key) {
        return getP(key).subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
    }

    public static BigInteger getQ(PrivateKey key) {
        return getP(key).subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
    }

    public static BigInteger getG(PublicKey key) {
        return ((DHPublicKey) key).getParams().getG();
    }
    
    public static BigInteger getG(PrivateKey key) {
        return ((DHPrivateKey) key).getParams().getG();
    }
    
    public static BigInteger getY(PublicKey key) {
        return ((DHPublicKey) key).getY();
    }

    public static BigInteger getX(PrivateKey key) {
        return ((DHPrivateKey) key).getX();
    }
    
    public static BigInteger getH(PublicKey keyPublic, PrivateKey keyPrivate) {
        return getG(keyPublic).modPow(getX(keyPrivate), getP(keyPublic));
    }
}
