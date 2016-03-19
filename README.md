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

You can also get a hashed password, identify the hashing algorithm, and verify the password as follows:

```javascript
var hashers = require('node-django-hashers');

var hash_password = "pbkdf2_sha256$24000$EqklNbs3N4lg$COOpqEopVFNhBr20UOtUIm63RGYnX/0efMcNAEOFo50=";
var hash_name = hashers.identifyHasher(hash_password);
var hash_algorithm = hashers.getHasher(hash_name);
console.log(hash_algorithm.verify("password", hash_password)); // returns true
console.log(hash_algorithm.verify("wrong_password", hash_password)); // returns false
```

Similar approach to the above code sample can be used for all the other algorithms.

# Installation
```ssh
npm install node-django-hashers
```
