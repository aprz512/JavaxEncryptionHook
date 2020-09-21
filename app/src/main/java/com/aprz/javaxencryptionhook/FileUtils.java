package com.aprz.javaxencryptionhook;

import android.app.Activity;
import android.os.Environment;
import android.util.Log;
import android.widget.TextView;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

import de.robv.android.xposed.XposedBridge;

public class FileUtils {

    private static final String TAG = "FileUtils";

    private static File createLogFile(String packageName) {
        String cachePath = Environment.getExternalStorageDirectory().getPath() + "/Android/data/" + packageName + "/cache";
        File cacheDir = new File(cachePath);
        cacheDir.mkdir();
        String logPath = cachePath + "/log.txt";
        File logFile = new File(logPath);
        try {
            logFile.createNewFile();
            return logFile;
        } catch (IOException e) {
            Log.e(TAG, "创建日志文件失败了...-->" + logPath);
            e.printStackTrace();
        }

        return null;
    }

    public static void log(String packageName, String info, byte[] data, Throwable throwable) {

        File logFile = createLogFile(packageName);
        if (logFile != null) {
            try {
                info = info + "\n";
                info = info + getStack(throwable) + "\n";
                info = info + HexDumper.dumpHexString(data) + "\n------------------------------------------------------------------------------------------------------------------------\n\n";
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
                info += "↓↓↓↓↓↓↓↓   iv   ↓↓↓↓↓↓↓↓ \n";
                info += HexDumper.dumpHexString(iv) + "\n";
                info += "↓↓↓↓↓↓↓↓   result   ↓↓↓↓↓↓↓↓ \n";
                info += HexDumper.dumpHexString(result) + "\n------------------------------------------------------------------------------------------------------------------------\n\n";
                FileWriter fw = new FileWriter(logFile, true);
                fw.write(info);
                fw.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

//    public static String getStack() {
//        String result = "";
//        Throwable ex = new Throwable();
//        StackTraceElement[] stackElements = ex.getStackTrace();
//
//        int range_start = 5;
//        int range_end = Math.min(stackElements.length, 7);
//        if (range_end < range_start)
//            return "";
//
//        for (int i = range_start; i < range_end; i++) {
//            result = result + (stackElements[i].getClassName() + "->");
//            result = result + (stackElements[i].getMethodName()) + "  ";
//            result = result + (stackElements[i].getFileName() + "(");
//            result = result + (stackElements[i].getLineNumber() + ")\n");
//            result = result + ("-----------------------------------\n");
//        }
//        return result;
//    }

    private static String getStack(Throwable e) {

        //Write a printable representation of this Throwable
        //The StringWriter gives the lock used to synchronize access to this writer.
        final Writer stringBuffSync = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(stringBuffSync);
        e.printStackTrace(printWriter);
        String stacktrace = stringBuffSync.toString();
        printWriter.close();

        return stacktrace;


    }


}
