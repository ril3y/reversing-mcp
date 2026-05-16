package com.crackme;

class Checker {

    private static final byte KEY = 0x5A;

    private static final byte[] PART_A = {
        (byte)0x3C, (byte)0x36, (byte)0x3B, (byte)0x3D, (byte)0x21,
        (byte)0x39, (byte)0x36, (byte)0x6E, (byte)0x2F, (byte)0x3E,
        (byte)0x69
    };

    private static final byte[] PART_B = {
        (byte)0x05, (byte)0x28, (byte)0x3F, (byte)0x6E, (byte)0x3E,
        (byte)0x29, (byte)0x05, (byte)0x30, (byte)0x3B, (byte)0x3E,
        (byte)0x22, (byte)0x27
    };

    static boolean checkPartA(String s) {
        if (s.length() < PART_A.length) return false;
        for (int i = 0; i < PART_A.length; i++) {
            if (((s.charAt(i) ^ KEY) & 0xff) != (PART_A[i] & 0xff)) return false;
        }
        return true;
    }

    static boolean checkPartB(String s) {
        int offset = PART_A.length;
        if (s.length() != offset + PART_B.length) return false;
        for (int i = 0; i < PART_B.length; i++) {
            if (((s.charAt(offset + i) ^ KEY) & 0xff) != (PART_B[i] & 0xff)) return false;
        }
        return true;
    }

    static boolean verify(String s) {
        return checkPartA(s) && checkPartB(s);
    }
}
