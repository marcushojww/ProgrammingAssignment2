## The Problem

---

- ### There is a need to verify if the person you are trying to establish a connection with is the actual server and not a malicious attacker.
- ### After receiving the server's certificate as seen in Fig 1, we need to verify the certificate with the CA's public key as the server certificate might not be verified by the CA.
- ### If the certificate is not verified, then we cannot tell if the server we are trying to establish a connection with is actually the server.

<br />

## The Solution

---

- ### The Server sends the Client a Base64 encoded Server Certificate in the form of a String type to ensure confidentiality.
- ### Upon receiving the certificate, the Client decodes it and obtains the Server certificate.
- ### In order to verify the Server certificate, we use the verify(PublicKey key) abstract method which is used to verify a signed certificate.
- ### Hence, we pass the CA's public key as the argument for the ServerCertificate.verify() method and check if the certificate is indeed verified.
