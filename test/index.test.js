
const hashers = require('../index');
const assert = require('assert');


describe('getHashers test with all hashing algorithms', () => {
    it ('testing unsalted_md5', () => {
        const hash_password = "5f4dcc3b5aa765d61d8327deb882cf99";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'unsalted_md5', 'Testing unsalted_md5 from Django');
    });

    it ('testing unsalted_sha1', () => {
        const hash_password = "sha1$$5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'unsalted_sha1', 'Testing unsalted_sha1 from Django');
    });

    it ('testing sha1', () => {
        const hash_password = "sha1$vCl9KSmkkKHJ$3864dc6b8ea10d757290660df171a0f7c5fc3b36";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'sha1', 'Testing sha1 from Django');
    });

    it ('testing md5', () => {
        const hash_password = "md5$UyDBYR3ttBkN$510f43d5da1a0ef16ed4ef361cbfef5e";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'md5', 'Testing md5 from Django');
    });

    it ('testing pbkdf2_sha256', () => {
        const hash_password = "pbkdf2_sha256$36000$c8SBx74kl0XA$bAmKN/CgJGlh7xpuxmvQX9ypsnjV68JqZlfLxWDYGBk=";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'pbkdf2_sha256', 'Testing pbkdf2_sha256 from Django');
    });

    it ('testing argon2', () => {
        const hash_password = "argon2$argon2i$v=19$m=512,t=2,p=2$UXZPOFhoSUxrWmhQ$CCPcRG8t+LOJB8H1zL+Prw";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'argon2', 'Testing argon2 from Django');
    });

    it ('testing pbkdf2_sha1', () => {
        const hash_password = "pbkdf2_sha1$36000$P6Y4I7YXzZpB$LrWCTPqWtIdPFYY5jt+w56QJGR0=";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'pbkdf2_sha1', 'Testing pbkdf2_sha1 from Django');
    });

    it ('testing bcrypt_sha256', () => {
        const hash_password = "bcrypt_sha256$$2b$12$7swZEQstS0pPWpvL4LQ/guW75Lc8OCRY1V1zq17jUlsQqyLhVuzGa";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'bcrypt_sha256', 'Testing bcrypt_sha256 from Django');
    });

    it ('testing bcrypt', () => {
        const hash_password = "bcrypt$$2b$12$QssVJfXwb178/8i1CUMTsOoRhi7.oFF5FVdxbM1ZxCnd6iDfTZaVO";
        const h = hashers.identifyHasher(hash_password);
        assert.equal(h, 'bcrypt', 'Testing bcrypt from Django');
    });
});

describe('Test all password hashing algorithms encode and verify methods', () => {
    it ('testing unsalted_md5 encode', async () => {
        const h = new hashers.UnsaltedMD5PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing unsalted_md5 encode and verify from Django');
    });

    it ('testing unsalted_sha1 encode', async () => {
        const h = new hashers.UnsaltedSHA1PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing unsalted_sha1 encode and verify from Django');
    });

    it ('testing sha1 encode', async () => {
        const h = new hashers.SHA1PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing sha1 encode and verify from Django');
    });

    it ('testing md5 encode', async () => {
        const h = new hashers.MD5PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing md5 encode and verify from Django');
    });

    it ('testing pbkdf2_sha256 encode', async () => {
        const h = new hashers.PBKDF2PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing pbkdf2_sha256 encode and verify from Django');
    });

    it ('testing argon2 encode', async () => {
        const h = new hashers.Argon2PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing argon2 encode and verify from Django');
    });

    it ('testing pbkdf2_sha1 encode', async () => {
        const h = new hashers.PBKDF2SHA1PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing pbkdf2_sha1 encode and verify from Django');
    });

    it ('testing bcrypt_sha256 encode', async () => {
        const h = new hashers.BCryptSHA256PasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing bcrypt_sha256 encode and verify from Django');
    });

    it ('testing bcrypt encode', async () => {
        const h = new hashers.BCryptPasswordHasher();
        const hashPassword = await h.encode('password');
        const verify = await h.verify('password', hashPassword);
        assert.equal(verify, true, 'Testing bcrypt encode and verify from Django');
    });
});

