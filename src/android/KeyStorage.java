package com.securekeystore.plugin;

// Helper function for storing keys to internal storage.

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public final class KeyStorage {

    public static void writeKeyConfig(Context context, String keyAlias, String numberPart)  {
        try {
            FileOutputStream fos = context.openFileOutput(Constants.SKS_FILENAME + keyAlias + "_CONFIG", context.MODE_PRIVATE);
            fos.write(numberPart.getBytes("UTF-8"));
            fos.close();
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception saveKeyConfig: " + e.getMessage());
        }
    }

    public static String readKeyConfig(Context context, String keyAlias) {
        try {
            FileInputStream fis = context.openFileInput(Constants.SKS_FILENAME + keyAlias + "_CONFIG");
            byte[] buffer = new byte[8192];
            int bytesRead;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            byte[] numberTextBytes = bos.toByteArray();
            String numberString = new String(numberTextBytes, 0, numberTextBytes.length, "UTF-8");
            fis.close();
            return numberString;
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception readKeyConfig: "  + e.getMessage());
            return "0";
        }
    }

    public static void writeValues(Context context, String keyAlias, String part, byte[] vals)  {
        try {
            FileOutputStream fos = context.openFileOutput(Constants.SKS_FILENAME + keyAlias + part, context.MODE_PRIVATE);
            String s = new String(vals);
            fos.write(vals);
            fos.close();
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception writeValues: " + e.getMessage());
        }
    }

    public static byte[] readValues(Context context, String keyAlias, String part) {
        try {
            FileInputStream fis = context.openFileInput(Constants.SKS_FILENAME + keyAlias + part);
            byte[] buffer = new byte[8192];
            int bytesRead;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            byte[] cipherText = bos.toByteArray();
            fis.close();
            return cipherText;
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception readValues: "  + e.getMessage());
            return new byte[0];
        }
    }

    public static void resetValues(Context context, String keyAlias)  {
        try {
            String numberPartStr = readKeyConfig(context, keyAlias);
            int numberParts = Integer.parseInt(numberPartStr);
            if(numberParts > 0){
                for(int n = 0; n < numberParts; n++){
                    /*
                    Log.i(Constants.TAG, Constants.SKS_FILENAME + keyAlias + n);
                    boolean returnFlag = context.deleteFile(Constants.SKS_FILENAME + keyAlias + n);
                    Log.i(Constants.TAG, returnFlag+"");
                    */

                    String dir = context.getFilesDir().getAbsolutePath();
                    File f0 = new File(dir, Constants.SKS_FILENAME + keyAlias + n);
                    boolean d0 = f0.delete(); 
                    Log.i(Constants.TAG, "File deleted: " + d0);
                }
            }
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception resetValues: " + e.getMessage());
        }

    }    

}