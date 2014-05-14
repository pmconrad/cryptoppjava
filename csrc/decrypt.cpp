#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>

#include "de_quisquis_ec_impl_pp_CryptoppNative.h"
#include "curves.h"
#include "helpers.h"

extern "C" {

JNIEXPORT jbyteArray JNICALL Java_de_quisquis_ec_impl_pp_CryptoppNative_decrypt
  (JNIEnv *env, jclass nativeClass, jbyteArray ciphertext, jbyteArray modulus,
   jbyteArray a, jbyteArray b, jbyteArray gX, jbyteArray gY, jbyteArray n,
   jbyteArray x) {

    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decrypter;
    initPrivateKey(env, decrypter.AccessKey(), modulus, a, b, gX, gY, n, x);

    jbyte *cipherBytes = env->GetByteArrayElements(ciphertext, NULL);
    if (cipherBytes == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    const jsize cipherLen = env->GetArrayLength(ciphertext);
    byte plainBuf[decrypter.MaxPlaintextLength(cipherLen)];
    CryptoPP::DecodingResult result = decrypter.Decrypt(prng, cipherBytes,
                                                        cipherLen, plainBuf);
    env->ReleaseByteArrayElements(ciphertext, cipherBytes, 0);

    if (!result.isValidCoding) {
        return NULL; // FIXME: throw exception
    }
    jbyteArray plaintext = env->NewByteArray(result.messageLength);
    if (plaintext == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    jbyte *bytes = env->GetByteArrayElements(plaintext, NULL);
    if (bytes == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    memcpy(bytes, plainBuf, result.messageLength);
    env->ReleaseByteArrayElements(plaintext, bytes, 0);
    return plaintext;
}

} /* extern "C" */
