#include <cryptopp/eccrypto.h>
#include <cryptopp/validate.h>

#include "de_quisquis_ec_impl_pp_CryptoppNative.h"
#include "curves.h"
#include "helpers.h"

extern "C" {

JNIEXPORT jbyteArray JNICALL Java_de_quisquis_ec_impl_pp_CryptoppNative_encrypt
  (JNIEnv *env, jclass theClass, jbyteArray plaintext, jbyteArray modulus,
   jbyteArray a, jbyteArray b, jbyteArray gX, jbyteArray gY, jbyteArray n,
   jbyteArray qX, jbyteArray qY) {

    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encrypter;
    initPublicKey(env, encrypter.AccessKey(),
                  modulus, a, b, gX, gY, n, qX, qY);

    jbyte *plainBytes = env->GetByteArrayElements(plaintext, NULL);
    if (plainBytes == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    jsize plainLen = env->GetArrayLength(plaintext);
    size_t cipherLen = encrypter.CiphertextLength(plainLen);
    jbyteArray result = env->NewByteArray(cipherLen);
    if (result == NULL) {
	// FIXME: check/throw exception
    } else {
        jbyte *bytes = env->GetByteArrayElements(result, NULL);
        if (bytes == NULL) {
            // FIXME: check/throw exception
        } else {
            encrypter.Encrypt(GlobalRNG(), plainBytes, plainLen, bytes);
            env->ReleaseByteArrayElements(result, bytes, 0);
        }
    }
    env->ReleaseByteArrayElements(plaintext, plainBytes, JNI_ABORT);
}

} /* extern "C" */
