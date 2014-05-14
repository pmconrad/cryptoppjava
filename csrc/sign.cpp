#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>

#include "de_quisquis_ec_impl_pp_CryptoppNative.h"
#include "curves.h"
#include "helpers.h"

extern "C" {

JNIEXPORT jbyteArray JNICALL Java_de_quisquis_ec_impl_pp_CryptoppNative_sign
  (JNIEnv *env, jclass nativeClass, jbyteArray message, jbyteArray modulus,
   jbyteArray a, jbyteArray b, jbyteArray gX, jbyteArray gY, jbyteArray n,
   jbyteArray x) {

    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA1>::Signer signer;
    initPrivateKey(env, signer.AccessKey(), modulus, a, b, gX, gY, n, x);

    jbyte *msgBytes = env->GetByteArrayElements(message, NULL);
    if (msgBytes == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    size_t siglen = signer.MaxSignatureLength();
    byte sigBuf[siglen];
    siglen = signer.SignMessage(prng, msgBytes, env->GetArrayLength(message),
                                sigBuf);
    env->ReleaseByteArrayElements(message, msgBytes, JNI_ABORT);

    jbyteArray sig = env->NewByteArray(siglen);
    if (sig == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    jbyte *bytes = env->GetByteArrayElements(sig, NULL);
    if (bytes == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    memcpy(bytes, sigBuf, siglen);
    env->ReleaseByteArrayElements(sig, bytes, 0);
    return sig;
}

} /* extern "C" */
