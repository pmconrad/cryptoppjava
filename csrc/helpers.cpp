#include "helpers.h"

jbyteArray integerToByteArray(JNIEnv *env, const CryptoPP::Integer &number) {
    size_t len = number.MinEncodedSize(CryptoPP::Integer::SIGNED);
    jbyteArray result = env->NewByteArray(len);
    if (result == NULL) {
	return result; // FIXME: check/throw exception
    }
    jbyte *bytes = env->GetByteArrayElements(result, NULL);
    if (bytes == NULL) {
	return NULL; // FIXME: check/throw exception
    }
    number.Encode(bytes, len, CryptoPP::Integer::SIGNED);
    env->ReleaseByteArrayElements(result, bytes, 0);
    return result;
}

CryptoPP::Integer byteArrayToInteger(JNIEnv *env, const jbyteArray &array) {
    jbyte *bytes = env->GetByteArrayElements(array, NULL);
    if (bytes == NULL) {
	return NULL; // FIXME: check/throw exception
    }
    CryptoPP::Integer result(bytes, env->GetArrayLength(array),
			     CryptoPP::Integer::SIGNED);
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

void initPrivateKey(const JNIEnv *env,
		    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> &key,
		    const jbyteArray &modulus, const jbyteArray &a,
		    const jbyteArray &b, const jbyteArray &gX,
		    const jbyteArray &gY, const jbyteArray &n,
		    const jbyteArray &x) {
}

void initPublicKey(const JNIEnv *env,
		   CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> &key,
		   const jbyteArray &modulus, const jbyteArray &a,
		   const jbyteArray &b, const jbyteArray &gX,
		   const jbyteArray &gY, const jbyteArray &n,
		   const jbyteArray &qX, const jbyteArray &qY) {
}
