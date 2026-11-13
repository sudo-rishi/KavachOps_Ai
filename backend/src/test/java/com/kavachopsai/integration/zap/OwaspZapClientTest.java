package com.kavachopsai.integration.zap;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class OwaspZapClientTest {

    @Test
    void rejectsNonHttpTargetsBeforeContactingZap() {
        OwaspZapClient client = new OwaspZapClient(
                "http://localhost:8080", "", true, 2000, 900);

        assertThrows(IllegalArgumentException.class, () -> client.scanUrl("file:///C:/Windows"));
    }

    @Test
    void rejectsMalformedTargetsBeforeContactingZap() {
        OwaspZapClient client = new OwaspZapClient(
                "http://localhost:8080", "", true, 2000, 900);

        assertThrows(IllegalArgumentException.class, () -> client.scanUrl("not a URL"));
    }
}
