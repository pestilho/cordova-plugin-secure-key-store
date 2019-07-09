package com.securekeystore.plugin;

// Secure key store main class

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Context;
import android.util.Log;
import android.util.Base64;
import android.security.KeyPairGeneratorSpec;
import android.os.Build;

import java.security.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.StringBuffer;
import java.util.Calendar;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

public class SecureKeyStore extends CordovaPlugin {

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {

        if (action.equals("set")) {
            String alias = args.getString(0);
            String input = args.getString(1);
            this.encrypt(alias, input, callbackContext);
            return true;
        }

        if (action.equals("get")) {
            String alias = args.getString(0);
            this.decrypt(alias, callbackContext);
            return true;
        }

        if (action.equals("remove")) {
            String alias = args.getString(0);
            this.removeKeyFile(alias, callbackContext);
            return true;
        }

        return false;
    }

    private void encrypt(String alias, String input, CallbackContext callbackContext) {

        try {

            KeyStore keyStore = KeyStore.getInstance(getKeyStore());
            keyStore.load(null);

            if (!keyStore.containsAlias(alias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(getContext()).setAlias(alias)
                        .setSubject(new X500Principal("CN=" + alias)).setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime()).setEndDate(end.getTime()).build();

                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", getKeyStore());
                generator.initialize(spec);

                KeyPair keyPair = generator.generateKeyPair();

                Log.i(Constants.TAG, "created new key pairs");
            }

            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

            if (input.isEmpty()) {
                Log.d(Constants.TAG, "Exception: input text is empty");
                return;
            }

            Cipher cipher = Cipher.getInstance(Constants.RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] rawinputData = input.getBytes("UTF-8");
            byte[][] keyParts = divideArray(rawinputData, 128);
            byte[][] keyEncryptedParts = new byte[keyParts.length][];
            Log.i(Constants.TAG, "keyParts: " + keyParts.length);
            
            for(int p = 0; p < keyParts.length; p++){
                keyEncryptedParts[p] = cipher.doFinal(keyParts[p]);
            }

            String separatorString = new String("###");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] separatorBytes = separatorString.getBytes("UTF-8");
            for(int p = 0; p < keyEncryptedParts.length; p++){
                outputStream.write(keyEncryptedParts[p]);
                if(p < keyEncryptedParts.length - 1){
                    outputStream.write(separatorBytes);
                }
            }
            //byte[] encryptedBytes = cipher.doFinal(rawinputData);

            //String s = new String(keyEncryptedParts[0]);
            //Log.i(Constants.TAG, "ENCRYPT MESSAGEM: " + s);

            /*
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            cipherOutputStream.write(input.getBytes("UTF-8"));
            cipherOutputStream.close();
            byte[] vals = outputStream.toByteArray();
            */
            byte[] vals = outputStream.toByteArray();


            // writing key to storage
            //byte[] byteArray = input.getBytes("UTF-8");
            //String s = new String(encryptedBytes);
            Log.i(Constants.TAG, "LENGTH rawinputData: " + rawinputData.length);
            Log.i(Constants.TAG, "LENGTH vals: " + vals.length);
            //Log.i(Constants.TAG, "MESSAGEM: " + s);
            KeyStorage.writeValues(getContext(), alias, vals);
            Log.i(Constants.TAG, "key created and stored successfully");
            callbackContext.success("key created and stored successfully");

        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception: " + e.getMessage());
            Log.e(Constants.TAG, Log.getStackTraceString(e));
            callbackContext.error(
                    "{\"code\": 9, \"api-level\": " + Build.VERSION.SDK_INT + ",\"message\": \"" + e.getMessage() + "\"}");
        }

    }

    private void decrypt(String alias, CallbackContext callbackContext) {

        try {

            KeyStore keyStore = KeyStore.getInstance(getKeyStore());
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

            Cipher cipher = Cipher.getInstance(Constants.RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] rawoutputData = KeyStorage.readValues(getContext(), alias);

            
            Log.i(Constants.TAG, "LENGTH rawoutputData: " + rawoutputData.length);
            String rawoutputText = new String(rawoutputData, 0, rawoutputData.length, "UTF-8");
            Log.i(Constants.TAG, "TEXT rawoutputData: " + rawoutputText);
            String[] keyStringParts = rawoutputText.split("###");
            byte[][] keyEncryptedParts = new byte[keyStringParts.length][];
            byte[][] keyDecryptedParts = new byte[keyStringParts.length][];
            Log.i(Constants.TAG, "keyEncryptedParts: " + keyStringParts.length);

            for(int p = 0; p < keyStringParts.length; p++){
                byte[] encryptedPart = parseHexBinary(keyStringParts[p]);
                Log.i(Constants.TAG, "BLOCK LENGTH: " + encryptedPart.length);
                keyDecryptedParts[p] = cipher.doFinal(encryptedPart);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            for(int p = 0; p < keyDecryptedParts.length; p++){
                outputStream.write(keyDecryptedParts[p]);
            }
            byte[] decryptedBytes = outputStream.toByteArray();
            Log.i(Constants.TAG, "LENGTH decryptedBytes: " + decryptedBytes.length);
            

            //byte[] decryptedBytes = cipher.doFinal(rawoutputData);

            /*
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(KeyStorage.readValues(getContext(), alias)), output);

            ArrayList<Byte> values = new ArrayList<Byte>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }
            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }
            */

            String finalText = new String(decryptedBytes, 0, decryptedBytes.length, "UTF-8");
            Log.i(Constants.TAG, "TEXT finalText: " + finalText);
            callbackContext.success(finalText);

        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception: " + e.getMessage());
            Log.e(Constants.TAG, Log.getStackTraceString(e));
            callbackContext.error(
                    "{\"code\": 1, \"api-level\": " + Build.VERSION.SDK_INT + ", \"message\": \"" + e.getMessage() + "\"}");
        }
    }

    private void removeKeyFile(String alias, CallbackContext callbackContext) {
        try {
            KeyStorage.resetValues(getContext(), alias);
            Log.i(Constants.TAG, "keys removed successfully");
            callbackContext.success("keys removed successfully");

        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception: " + e.getMessage());
            callbackContext.error(
                    "{\"code\": 6, \"api-level\": " + Build.VERSION.SDK_INT + ", \"message\": \"" + e.getMessage() + "\"}");
        }
    }

    private Context getContext() {
        return cordova.getActivity().getApplicationContext();
    }

    private String getKeyStore() {
        try {
            KeyStore.getInstance(Constants.KEYSTORE_PROVIDER_1);
            return Constants.KEYSTORE_PROVIDER_1;
        } catch (Exception err) {
            try {
                KeyStore.getInstance(Constants.KEYSTORE_PROVIDER_2);
                return Constants.KEYSTORE_PROVIDER_2;
            } catch (Exception e) {
                return Constants.KEYSTORE_PROVIDER_3;
            }
        }
    }

    private static byte[][] divideArray(byte[] source, int chunksize) {
        byte[][] ret = new byte[(int)Math.ceil(source.length / (double)chunksize)][chunksize];
        int start = 0;

        for(int i = 0; i < ret.length; i++) {
            ret[i] = Arrays.copyOfRange(source,start, start + chunksize);
            start += chunksize ;
        }

        return ret;
    }

    private static byte[] parseHexBinary(String hexText){
        String binaryText = new BigInteger(hexText, 16).toString(2);
        return binaryText.getBytes("UTF-8");
    }

}
