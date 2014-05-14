#include <jni.h>
#include <cryptopp/integer.h>
#include <cryptopp/eccrypto.h>

extern jbyteArray integerToByteArray(const JNIEnv *env,
				     const CryptoPP::Integer &number);

extern CryptoPP::Integer byteArrayToInteger(const JNIEnv *env,
					    const jbyteArray &array);

extern void initPrivateKey(const JNIEnv *env,
			   CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> &key,
			   const jbyteArray &modulus, const jbyteArray &a,
			   const jbyteArray &b, const jbyteArray &gX,
			   const jbyteArray &gY, const jbyteArray &n,
			   const jbyteArray &x);

extern void initPublicKey(const JNIEnv *env,
			  CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> &key,
			  const jbyteArray &modulus, const jbyteArray &a,
			  const jbyteArray &b, const jbyteArray &gX,
			  const jbyteArray &gY, const jbyteArray &n,
			  const jbyteArray &qX, const jbyteArray &qY);
