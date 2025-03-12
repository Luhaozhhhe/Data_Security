#include "examples.h"
#include <iostream>
#include <vector>
#include <cmath>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// 定义常量 N
const int N = 3;

// 打印向量函数
void printVector(const vector<double>& vec, int precision = 3) {
    cout << fixed << setprecision(precision);
    cout << "{ ";
    for (size_t i = 0; i < vec.size(); ++i) {
        cout << vec[i];
        if (i < vec.size() - 1) {
            cout << ", ";
        }
    }
    cout << " }" << endl;
}

// 打印当前行号及信息
void printCurrentLine(int line, const string& message = "") {
    cout << "Line " << line << ": " << message << endl;
}

int main() {
    // 初始化待计算的向量
    vector<double> vectorX = {1.0, 2.0, 3.0};
    vector<double> vectorY = {2.0, 3.0, 4.0};
    vector<double> vectorZ = {3.0, 4.0, 5.0};

    // 输出原始向量信息
    cout << "原始向量 x 为：" << endl;
    printVector(vectorX);
    cout << "原始向量 y 为：" << endl;
    printVector(vectorY);
    cout << "原始向量 z 为：" << endl;
    printVector(vectorZ);
    cout << endl;

    // 配置加密参数
    EncryptionParameters encryptionParams(scheme_type::ckks);
    size_t polynomialModulusDegree = 8192;
    encryptionParams.set_poly_modulus_degree(polynomialModulusDegree);
    encryptionParams.set_coeff_modulus(CoeffModulus::Create(polynomialModulusDegree, {60, 40, 40, 60}));
    double encodingScale = pow(2.0, 40);

    // 创建 CKKS 上下文
    SEALContext sealContext(encryptionParams);

    // 生成密钥
    KeyGenerator keyGenerator(sealContext);
    auto privateKey = keyGenerator.secret_key();
    PublicKey publicKey;
    keyGenerator.create_public_key(publicKey);
    RelinKeys relinearizationKeys;
    keyGenerator.create_relin_keys(relinearizationKeys);

    // 构建加密、解密、编码和评估器
    Encryptor encryptor(sealContext, publicKey);
    Evaluator evaluator(sealContext);
    Decryptor decryptor(sealContext, privateKey);
    CKKSEncoder encoder(sealContext);

    // 对向量进行编码
    Plaintext plainX, plainY, plainZ;
    encoder.encode(vectorX, encodingScale, plainX);
    encoder.encode(vectorY, encodingScale, plainY);
    encoder.encode(vectorZ, encodingScale, plainZ);

    // 对编码后的明文进行加密
    Ciphertext encryptedX, encryptedY, encryptedZ;
    encryptor.encrypt(plainX, encryptedX);
    encryptor.encrypt(plainY, encryptedY);
    encryptor.encrypt(plainZ, encryptedZ);

    // 计算 x^2
    printCurrentLine(__LINE__, "开始计算 x^2");
    Ciphertext squaredX;
    evaluator.multiply(encryptedX, encryptedX, squaredX);
    evaluator.relinearize_inplace(squaredX, relinearizationKeys);
    evaluator.rescale_to_next_inplace(squaredX);
    printCurrentLine(__LINE__, "x^2 的模数链索引为: " + 
        to_string(sealContext.get_context_data(squaredX.parms_id())->chain_index()));

    // 调整 encryptedX 的层级
    printCurrentLine(__LINE__, "encryptedX 的模数链索引为: " + 
        to_string(sealContext.get_context_data(encryptedX.parms_id())->chain_index()));
    printCurrentLine(__LINE__, "开始计算 1.0 * x 以调整层级");
    Plaintext plainOne;
    encoder.encode(1.0, encodingScale, plainOne);
    evaluator.multiply_plain_inplace(encryptedX, plainOne);
    evaluator.rescale_to_next_inplace(encryptedX);
    printCurrentLine(__LINE__, "调整后 encryptedX 的模数链索引为: " + 
        to_string(sealContext.get_context_data(encryptedX.parms_id())->chain_index()));

    // 计算 x^3
    printCurrentLine(__LINE__, "开始计算 x^3");
    Ciphertext cubedX;
    evaluator.multiply(squaredX, encryptedX, cubedX);
    evaluator.relinearize_inplace(cubedX, relinearizationKeys);
    evaluator.rescale_to_next_inplace(cubedX);
    printCurrentLine(__LINE__, "x^3 的模数链索引为: " + 
        to_string(sealContext.get_context_data(cubedX.parms_id())->chain_index()));

    // 计算 y * z
    printCurrentLine(__LINE__, "开始计算 y * z");
    Ciphertext productYZ;
    evaluator.multiply(encryptedY, encryptedZ, productYZ);
    evaluator.relinearize_inplace(productYZ, relinearizationKeys);
    evaluator.rescale_to_next_inplace(productYZ);
    printCurrentLine(__LINE__, "y * z 的模数链索引为: " + 
        to_string(sealContext.get_context_data(productYZ.parms_id())->chain_index()));

    // 统一 scale
    printCurrentLine(__LINE__, "将 x^3 和 y * z 的 scale 统一为 2^40");
    cubedX.scale() = encodingScale;
    productYZ.scale() = encodingScale;
    printCurrentLine(__LINE__, "x^3 的精确 scale 为: " + to_string(cubedX.scale()));
    printCurrentLine(__LINE__, "y * z 的精确 scale 为: " + to_string(productYZ.scale()));

    // 调整 y * z 的层级与 x^3 一致
    parms_id_type targetParamsId = cubedX.parms_id();
    evaluator.mod_switch_to_inplace(productYZ, targetParamsId);
    printCurrentLine(__LINE__, "调整后 y * z 的模数链索引为: " + 
        to_string(sealContext.get_context_data(productYZ.parms_id())->chain_index()));

    // 计算 x^3 + y * z
    printCurrentLine(__LINE__, "开始计算 x^3 + y * z");
    Ciphertext encryptedResult;
    evaluator.add(cubedX, productYZ, encryptedResult);

    // 解密结果
    Plaintext plainResult;
    decryptor.decrypt(encryptedResult, plainResult);

    // 解码结果
    vector<double> result;
    encoder.decode(plainResult, result);

    // 输出最终结果
    printCurrentLine(__LINE__, "计算结果为：");
    print_vector(result, 3 /*precision*/);

    return 0;
}
