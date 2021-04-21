## The Problem

---

- ### There is a need to verify if the person you are trying to establish a connection with is the actual server and not a malicious attacker.
- ### Hence, we need to ensure that the server has the private key
<br />

## The Solution

---

- ### Client sends a message to the Server in the beginning, for example, "Hello Server, please prove your identity"
- ### After the message is sent, the Server is expected to encrypt it with it's private key. Then, the Server sends this encrypted message back to the Client.
- ### The Client reads this encrypted message, and decrypts it with the Server's public key obtained from the Server's certificate.
- ### Then, a check is performed to compare the decrypted message with the original message sent in the beginning.
- ### If the messages are equal, then authentication is a success and the server is verified to have the private key.
