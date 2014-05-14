#include <cryptopp/eccrypto.h>
#include <cryptopp/validate.h>

#include "de_quisquis_ec_impl_pp_CryptoppNative.h"
#include "curves.h"
#include "helpers.h"

extern "C" {

JNIEXPORT jboolean JNICALL Java_de_quisquis_ec_impl_pp_CryptoppNative_verify
  (JNIEnv *env, jclass nativeClass, jbyteArray message, jbyteArray signature,
   jbyteArray modulus, jbyteArray a, jbyteArray b, jbyteArray gX,
   jbyteArray gY, jbyteArray n, jbyteArray qX, jbyteArray qY) {

    bool result;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA1>::Verifier verifier;
    initPublicKey(env, verifier.AccessKey(), modulus, a, b, gX, gY, n, qX, qY);

    jbyte *msgBytes = env->GetByteArrayElements(message, NULL);
    if (msgBytes == NULL) {
        return NULL; // FIXME: check/throw exception
    }
    jbyte *sigBytes = env->GetByteArrayElements(signature, NULL);
    if (sigBytes == NULL) {
        // FIXME: check/throw exception
    } else {
        result = verifier.VerifyMessage(msgBytes, env->GetArrayLength(message),
                                        sigBytes, env->GetArrayLength(signature));
        env->ReleaseByteArrayElements(signature, sigBytes, JNI_ABORT);
    }
    env->ReleaseByteArrayElements(message, msgBytes, JNI_ABORT);
    return result;
}

} /* extern "C" */
