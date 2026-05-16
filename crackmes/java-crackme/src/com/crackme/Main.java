package com.crackme;

public class Main {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("usage: java -jar crackme.jar <flag>");
            System.exit(2);
        }
        if (Checker.verify(args[0])) {
            System.out.println("Correct!");
            System.exit(0);
        } else {
            System.out.println("Nope.");
            System.exit(1);
        }
    }
}
