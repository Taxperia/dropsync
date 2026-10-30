package com.dropsync.app;

import android.app.Activity;
import android.content.ClipData;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;

/** A separate app UID owns and shares the fixtures, like Photos or a file manager. */
public final class ShareSmokeSourceActivity extends Activity {
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            boolean multiple = getIntent().getBooleanExtra("multiple", false);
            ArrayList<Uri> uris = new ArrayList<>();
            uris.add(fixture(multiple ? "smoke-multi-one.bin" : "smoke-single.bin", multiple ? 31 : 600_003));
            if (multiple) uris.add(fixture("smoke-multi-two.bin", 0));
            Intent share = new Intent(multiple ? Intent.ACTION_SEND_MULTIPLE : Intent.ACTION_SEND)
                    .setClassName("com.dropsync.app", "com.dropsync.app.MainActivity")
                    .setType("application/octet-stream").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            if (multiple) share.putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris);
            else share.putExtra(Intent.EXTRA_STREAM, uris.get(0));
            ClipData clip = ClipData.newUri(getContentResolver(), "Shared fixtures", uris.get(0));
            for (int i=1; i<uris.size(); i++) clip.addItem(new ClipData.Item(uris.get(i)));
            share.setClipData(clip); startActivity(share);
        } catch (Exception error) { throw new IllegalStateException(error); }
        finish();
    }
    private Uri fixture(String name, int size) throws Exception {
        byte[] bytes = new byte[size]; for (int i=0;i<size;i++) bytes[i] = (byte)((i*31+7)&255);
        try (FileOutputStream output = new FileOutputStream(new File(getCacheDir(), name))) { output.write(bytes); }
        return Uri.parse("content://com.dropsync.app.test.files/" + name);
    }
}
