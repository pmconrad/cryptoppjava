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

static CryptoPP::ECPPoint getPoint(const JNIEnv *env, const jbyteArray &x,
                                   const jbyteArray &y) {
    return CryptoPP::ECPPoint(byteArrayToInteger(env, x),
                              byteArrayToInteger(env, y));
}

static CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>
        getGroupParameters(const JNIEnv *env, const jbyteArray &modulus,
                           const jbyteArray &a, const jbyteArray &b,
                           const jbyteArray &gX, const jbyteArray &gY,
                           const jbyteArray &n) {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
    params.Initialize(CryptoPP::ECP(byteArrayToInteger(env, modulus),
                                    byteArrayToInteger(env, a),
                                    byteArrayToInteger(env, b)),
                      getPoint(env, gX, gY), byteArrayToInteger(env, n));
    return params;
}

void initPrivateKey(const JNIEnv *env,
		    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> &key,
		    const jbyteArray &modulus, const jbyteArray &a,
		    const jbyteArray &b, const jbyteArray &gX,
		    const jbyteArray &gY, const jbyteArray &n,
		    const jbyteArray &x) {
    key.Initialize(getGroupParameters(env, modulus, a, b, gX, gY, n),
                   byteArrayToInteger(env, x));
}

void initPublicKey(const JNIEnv *env,
		   CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> &key,
		   const jbyteArray &modulus, const jbyteArray &a,
		   const jbyteArray &b, const jbyteArray &gX,
		   const jbyteArray &gY, const jbyteArray &n,
		   const jbyteArray &qX, const jbyteArray &qY) {
    key.Initialize(getGroupParameters(env, modulus, a, b, gX, gY, n),
                   getPoint(env, qX, qY));
}
