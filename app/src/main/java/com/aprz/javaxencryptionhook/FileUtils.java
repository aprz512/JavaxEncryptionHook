package com.aprz.javaxencryptionhook;

import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

public class FileUtils {

    private static final String TAG = "FileUtils";

    private static File createLogFile(String packageName) {
        String dataPath = "/data/data/" + packageName + "/files";
        File dataDir = new File(dataPath);
        if (!dataDir.exists()) {
            boolean mkdirs = dataDir.mkdirs();
            if (!mkdirs) {
                Log.e(TAG, "创建data目录失败了...-->" + dataPath);
            }
        }
        String logPath = dataPath + "/log.txt";
        File logFile = new File(logPath);
        if (!logFile.exists()) {
            try {
                logFile.createNewFile();
                return logFile;
            } catch (IOException e) {
                Log.e(TAG, "创建日志文件失败了...-->" + logPath);
                e.printStackTrace();
                return null;
            }
        } else {
            return logFile;
        }

    }

    public static void log(String packageName, String info, byte[] data, Throwable throwable) {

        File logFile = createLogFile(packageName);
        if (logFile != null) {
            try {
                info = info + "\n";
                info = info + getStack(throwable) + "\n";
                if (data != null) {
                    info = info + HexDumper.dumpHexString(data) + "\n------------------------------------------------------------------------------------------------------------------------\n\n";
                }
                FileWriter fw = new FileWriter(logFile, true);
                fw.write(info);
                fw.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    public static void log(String packageName, String info, byte[] iv, byte[] result, Throwable throwable) {

        File logFile = createLogFile(packageName);
        if (logFile != null) {
            try {
                info += "\n";
                info += getStack(throwable) + "\n";

                if (iv != null) {
                    info += "↓↓↓↓↓↓↓↓   iv   ↓↓↓↓↓↓↓↓ \n";
                    info += HexDumper.dumpHexString(iv) + "\n";
                }

                if (result != null) {
                    info += "↓↓↓↓↓↓↓↓   result   ↓↓↓↓↓↓↓↓ \n";
                    info += HexDumper.dumpHexString(result) + "\n------------------------------------------------------------------------------------------------------------------------\n\n";
                }

                FileWriter fw = new FileWriter(logFile, true);
                fw.write(info);
                fw.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    public static String getStack(Throwable e) {
        //Write a printable representation of this Throwable
        //The StringWriter gives the lock used to synchronize access to this writer.
        final Writer stringBuffSync = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(stringBuffSync);
        e.printStackTrace(printWriter);
        printWriter.close();
        String builder = e.getMessage() + ":\n" +
                stringBuffSync.toString();
        return builder;
    }


}
