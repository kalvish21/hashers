# hashers
All password hashing algorithms for Django implemented in javascript for nodejs projects.

# Supported Algorithms

1. PBKDF2PasswordHasher
2. PBKDF2SHA1PasswordHasher
3. BCryptSHA256PasswordHasher
4. BCryptPasswordHasher
5. SHA1PasswordHasher
6. MD5PasswordHasher
7. UnsaltedSHA1PasswordHasher
8. UnsaltedMD5PasswordHasher
9. CryptPasswordHasher

# Usage

A simple example just verifying and creating Django compatible passwords:

```javascript
var hashers = require('node-django-hashers');

var h = new hashers.PBKDF2PasswordHasher();
var hash1 = h.encode("password", h.salt());
console.log(h.verify("password", hash1)); // returns true
console.log(h.verify("wrong_password", hash1)); // returns false
```

You can also get a hashed password, identify the hashing algorithm, and verify the password. The below example is for PBKDF2PasswordHasher, a similar approach to the above code sample can be used for all the other algorithms.

```javascript
var hashers = require('node-django-hashers');

var hash_password = "pbkdf2_sha256$24000$EqklNbs3N4lg$COOpqEopVFNhBr20UOtUIm63RGYnX/0efMcNAEOFo50=";
var hash_name = hashers.identifyHasher(hash_password);
var hash_algorithm = hashers.getHasher(hash_name);
console.log(hash_algorithm.verify("password", hash_password)); // returns true
console.log(hash_algorithm.verify("wrong_password", hash_password)); // returns false
```

A good practice is to verify if the password is using the default algorithm, and update the password if necessary on the database. Every hashing algorithm has an algorithm name. You can pass it in and check if updates are required:

```javascript
var hashers = require('node-django-hashers');

var hash_password = "286755fad04869ca523320acce0dc6a4"; // "password" in md5
var mustUpdate = hashers.mustUpdateHashedPassword(hash_password, "pbkdf2_sha256");
// mustUpdate is true since we do not want MD5 hash passwords, pbkdf2_sha256 is the default

var hash_algorithm = hashers.getHasher("pbkdf2_sha256");
// update the users password in the database by re encoding the password here

var hash_password = h.encode("password", h.salt());
```



# Installation
```ssh
npm install node-django-hashers
```
