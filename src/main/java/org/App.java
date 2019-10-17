package org;

public class App {

  public static void main(String[] args) throws Exception {
    Node server = new Node();
    Node client = new Node();

    server.setReceiverPublicKey(client.getPublickey());

    client.setReceiverPublicKey(server.getPublickey());

    String data = "9528";

    String enc = server.encrypt(data);

    System.out.println("9528 is converted to " + enc);

    System.out.println(enc + " is converted to " + client.decrypt(enc));

  }
}
