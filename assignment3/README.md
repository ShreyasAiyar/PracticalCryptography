problem1
1.  go run dh-alice1/dh-alice1.go alice-msg.txt alice-secret.txt
2.  go run dh-bob/dh-bob.go alice-msg.txt bob-msg.txt
3.  go run dh-alice2/dh-alice2.go bob-msg.txt alice-secret.txt

problem2
1. go run elg-keygen/elg-keygen.go public-key secret-key
2. problem2 % go run elg-encrypt/elg-encrypt.go plaintext public-key ciphertext
3. problem2 % go run elg-decrypt/elg-decrypt.go ciphertext secret-key 

problem3
