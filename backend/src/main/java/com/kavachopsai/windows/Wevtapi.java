package com.kavachopsai.windows;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.W32APIOptions;

/**
 * JNA binding for the Windows Wevtapi.dll (Windows Event Log API).
 * Available on Windows Vista / Server 2008 and later.
 */
public interface Wevtapi extends Library {

    Wevtapi INSTANCE = Native.load("wevtapi", Wevtapi.class, W32APIOptions.DEFAULT_OPTIONS);

    // EvtQuery flags
    int EvtQueryChannelPath        = 0x1;
    int EvtQueryFilePath           = 0x2;
    int EvtQueryForwardDirection   = 0x100;
    int EvtQueryReverseDirection   = 0x200;
    int EvtQueryTolerateQueryErrors = 0x1000;

    // EvtRender flags
    int EvtRenderEventValues = 0;
    int EvtRenderEventXml    = 1;
    int EvtRenderBookmark    = 2;

    /**
     * Opens a query on a channel or log file that you can then use to read events
     * that match the specified query criteria.
     */
    WinNT.HANDLE EvtQuery(
            WinNT.HANDLE session,
            String path,
            String query,
            int flags
    );

    /**
     * Gets the next set of events from the query results.
     */
    boolean EvtNext(
            WinNT.HANDLE resultSet,
            int eventsSize,
            WinNT.HANDLE[] events,
            int timeout,
            int flags,
            IntByReference returned
    );

    /**
     * Renders an event as an XML string or as values of specific elements.
     */
    boolean EvtRender(
            WinNT.HANDLE context,
            WinNT.HANDLE fragment,
            int flags,
            int bufferSize,
            Pointer buffer,
            IntByReference bufferUsed,
            IntByReference propertyCount
    );

    /**
     * Subscribes to receive future events or current+future events that match
     * the specified query criteria.
     */
    WinNT.HANDLE EvtSubscribe(
            WinNT.HANDLE session,
            WinNT.HANDLE signalEvent,
            String channelPath,
            String query,
            WinNT.HANDLE bookmark,
            Pointer context,
            EVT_SUBSCRIBE_CALLBACK callback,
            int flags
    );

    /**
     * Seeks to a specific event in a query result set.
     */
    boolean EvtSeek(
            WinNT.HANDLE resultSet,
            long position,
            WinNT.HANDLE bookmark,
            int timeout,
            int flags
    );

    /**
     * Opens a handle to a channel or log file that you can then use
     * to get information about the channel or log file.
     */
    WinNT.HANDLE EvtOpenLog(
            WinNT.HANDLE session,
            String path,
            int flags
    );

    /**
     * Closes an open handle.
     */
    boolean EvtClose(WinNT.HANDLE handle);

    /**
     * Callback interface for EvtSubscribe
     */
    interface EVT_SUBSCRIBE_CALLBACK extends com.sun.jna.Callback {
        int callback(int action, Pointer userContext, WinNT.HANDLE event);
    }

    // Subscribe flags
    int EvtSubscribeToFutureEvents    = 1;
    int EvtSubscribeStartAtOldestRecord = 2;
    int EvtSubscribeStartAfterBookmark = 3;

    // Error codes specific to Evt API
    int ERROR_EVT_CHANNEL_NOT_FOUND   = 0x3A98;
    int ERROR_EVT_INVALID_QUERY       = 0x3A9A;
    int ERROR_NO_MORE_ITEMS           = 259;
}

