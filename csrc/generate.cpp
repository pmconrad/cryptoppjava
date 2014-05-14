#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/validate.h>

#include "de_quisquis_ec_impl_pp_CryptoppNative.h"
#include "curves.h"
#include "helpers.h"

extern "C" {

JNIEXPORT jobject JNICALL Java_de_quisquis_ec_impl_pp_CryptoppNative_generate
  (JNIEnv *env, jclass clazz, jstring curvename) {
    const char *name = env->GetStringUTFChars(curvename, 0);
    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> key;
    key.GenerateRandom(GlobalRNG(),
		       CryptoPP::MakeParameters(CryptoPP::Name::GroupOID(),
					        curveByName(std::string(name))));
    env->ReleaseStringUTFChars(curvename, name);
    CryptoPP::ECPPoint q = key.GetGroupParameters()
                              .GetCurve().Multiply(key.GetPrivateExponent(),
                                                   key.GetGroupParameters()
                                                      .GetSubgroupGenerator());

    jclass ecData = env->FindClass("de/quisquis/ec/impl/pp/EcData");
    if (ecData == NULL) { return NULL; }
    jmethodID cons = env->GetMethodID(ecData, "<init>","([B[B[B[B[B[B[B[B[B)V");
    if (cons == NULL) { return NULL; }
    return env->NewObject(ecData, cons,
                          integerToByteArray(env, key.GetGroupParameters().GetCurve().FieldSize()),
                          integerToByteArray(env, key.GetGroupParameters().GetCurve().GetA()),
                          integerToByteArray(env, key.GetGroupParameters().GetCurve().GetB()),
                          integerToByteArray(env, key.GetGroupParameters().GetSubgroupGenerator().x),
                          integerToByteArray(env, key.GetGroupParameters().GetSubgroupGenerator().y),
                          integerToByteArray(env, key.GetGroupParameters().GetSubgroupOrder()),
                          integerToByteArray(env, q.x),
                          integerToByteArray(env, q.y),
                          integerToByteArray(env, key.GetPrivateExponent()));
}

} /* extern "C" */
